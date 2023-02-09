from __future__ import annotations
import shutil
from typing import Optional, Any, Tuple, List
import typing
import os
import logging
import time
import json
import tempfile
import string
import random
import tarfile
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import contextmanager
from passlib.hash import bcrypt
from zipfile import ZipFile, BadZipFile

from assemblyline.common import forge, log as al_log
from assemblyline.common.isotime import epoch_to_iso, now_as_iso
from assemblyline.common.identify import zip_ident
from assemblyline.odm.messages.changes import Operation, ServiceChange, SignatureChange
from assemblyline.remote.datatypes.events import EventSender, EventWatcher

from assemblyline_client import Client, get_client
from assemblyline_core.server_base import ThreadedCoreBase, ServiceStage
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.common.security import get_random_password, get_password_hash
from assemblyline.remote.datatypes.lock import Lock
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings

from assemblyline_v4_service.updater.helper import url_download, git_clone_repo, SkipSource


if typing.TYPE_CHECKING:
    import redis
    from assemblyline.odm.models.config import Config
    from assemblyline.datastore.helper import AssemblylineDatastore
    RedisType = redis.Redis[typing.Any]

SERVICE_PULL_INTERVAL = 1200
SERVICE_NAME = os.getenv('AL_SERVICE_NAME', 'service')

CONFIG_HASH_KEY = 'config_hash'
SOURCE_UPDATE_TIME_KEY = 'update_time'
LOCAL_UPDATE_TIME_KEY = 'local_update_time'
SOURCE_EXTRA_KEY = 'source_extra'
SOURCE_STATUS_KEY = 'status'
UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')
UI_SERVER_ROOT_CA = os.environ.get('UI_SERVER_ROOT_CA', '/etc/assemblyline/ssl/al_root-ca.crt')
UPDATER_DIR = os.getenv('UPDATER_DIR', os.path.join(tempfile.gettempdir(), 'updater'))
UPDATER_API_ROLES = ['signature_import', 'signature_download', 'signature_view', 'safelist_manage', 'apikey_access']

classification = forge.get_classification()


@contextmanager
def temporary_api_key(ds: AssemblylineDatastore, user_name: str, permissions=('R', 'W')):
    """Creates a context where a temporary API key is available."""
    with Lock(f'user-{user_name}', timeout=10):
        name = ''.join(random.choices(string.ascii_lowercase, k=20))
        random_pass = get_random_password(length=48)
        user = ds.user.get(user_name)
        user.apikeys[name] = {
            "password": bcrypt.hash(random_pass),
            "acl": permissions,
            "roles": UPDATER_API_ROLES
        }
        ds.user.save(user_name, user)

    try:
        yield f"{name}:{random_pass}"
    finally:
        with Lock(f'user-{user_name}', timeout=10):
            user = ds.user.get(user_name)
            user.apikeys.pop(name)
            ds.user.save(user_name, user)


class ServiceUpdater(ThreadedCoreBase):
    def __init__(self, logger: logging.Logger = None,
                 shutdown_timeout: float = None, config: Config = None,
                 datastore: AssemblylineDatastore = None,
                 redis: RedisType = None, redis_persist: RedisType = None,
                 default_pattern=".*"):

        self.updater_type = os.environ['SERVICE_PATH'].split('.')[-1].lower()
        self.default_pattern = default_pattern

        if not logger:
            al_log.init_logging(f'updater.{self.updater_type}', log_level=os.environ.get('LOG_LEVEL', "WARNING"))
            logger = logging.getLogger(f'assemblyline.updater.{self.updater_type}')

        super().__init__(f'assemblyline.{SERVICE_NAME}_updater', logger=logger, shutdown_timeout=shutdown_timeout,
                         config=config, datastore=datastore, redis=redis,
                         redis_persist=redis_persist)

        self.update_data_hash = Hash(f'service-updates-{SERVICE_NAME}', self.redis_persist)
        self._update_dir = None
        self._update_tar = None
        self._time_keeper = None
        self._service: Optional[Service] = None
        self.event_sender = EventSender('changes.services',
                                        host=self.config.core.redis.nonpersistent.host,
                                        port=self.config.core.redis.nonpersistent.port)

        self.service_change_watcher = EventWatcher(self.redis, deserializer=ServiceChange.deserialize)
        self.service_change_watcher.register(f'changes.services.{SERVICE_NAME}', self._handle_service_change_event)

        self.signature_change_watcher = EventWatcher(self.redis, deserializer=SignatureChange.deserialize)
        self.signature_change_watcher.register(f'changes.signatures.{SERVICE_NAME.lower()}',
                                               self._handle_signature_change_event)

        self.source_update_watcher = EventWatcher(self.redis)
        self.source_update_watcher.register(f'changes.sources.{SERVICE_NAME.lower()}',
                                            self._handle_source_update_event)

        # A event flag that gets set when an update should be run for
        # reasons other than it being the regular interval (eg, change in signatures)
        self.source_update_flag = threading.Event()
        self.local_update_flag = threading.Event()
        self.local_update_start = threading.Event()

        self._current_source: str = None

        # Load threads
        self._internal_server = None
        self.expected_threads = {
            'Sync Service Settings': self._sync_settings,
            'Outward HTTP Server': self._run_http,
            'Internal HTTP Server': self._run_internal_http,
            'Run source updates': self._run_source_updates,
            'Run local updates': self._run_local_updates,
        }
        # Only used by updater with 'generates_signatures: false'
        self.latest_updates_dir = os.path.join(UPDATER_DIR, 'latest_updates')
        if not os.path.exists(self.latest_updates_dir):
            os.makedirs(self.latest_updates_dir)

        # SSL configuration to UI_SERVER
        self.verify = None if not os.path.exists(UI_SERVER_ROOT_CA) else UI_SERVER_ROOT_CA

    def trigger_update(self):
        self.source_update_flag.set()

    def update_directory(self):
        return self._update_dir

    def update_tar(self):
        return self._update_tar

    def get_active_config_hash(self) -> int:
        return self.update_data_hash.get(CONFIG_HASH_KEY) or 0

    def set_active_config_hash(self, config_hash: int):
        self.update_data_hash.set(CONFIG_HASH_KEY, config_hash)

    def get_scheduled_update_time(self) -> float:
        return self.update_data_hash.get(SOURCE_UPDATE_TIME_KEY) or 0

    def set_scheduled_update_time(self, update_time):
        return self.update_data_hash.set(SOURCE_UPDATE_TIME_KEY, update_time)

    def get_source_update_time(self) -> float:
        return self.update_data_hash.get(f"{self._current_source}.{SOURCE_UPDATE_TIME_KEY}") or 0

    def set_source_update_time(self, update_time: float):
        self.update_data_hash.set(f"{self._current_source}.{SOURCE_UPDATE_TIME_KEY}", update_time)

    def get_source_extra(self) -> dict[str, Any]:
        return self.update_data_hash.get(f"{self._current_source}.{SOURCE_EXTRA_KEY}") or {}

    def set_source_extra(self, extra_data: dict[str, Any]):
        self.update_data_hash.set(f"{self._current_source}.{SOURCE_EXTRA_KEY}", extra_data)

    def get_local_update_time(self) -> float:
        if self._time_keeper:
            return os.path.getctime(self._time_keeper)
        return 0

    def status(self):
        return {
            'local_update_time': self.get_local_update_time(),
            'download_available': self._update_dir is not None,
            '_directory': self._update_dir,
            '_tar': self._update_tar,
        }

    def stop(self):
        super().stop()
        self.signature_change_watcher.stop()
        self.service_change_watcher.stop()
        self.source_update_watcher.stop()
        self.source_update_flag.set()
        self.local_update_flag.set()
        self.local_update_start.set()
        if self._internal_server:
            self._internal_server.shutdown()

    def try_run(self):
        self.signature_change_watcher.start()
        self.service_change_watcher.start()
        self.source_update_watcher.start()
        self.maintain_threads(self.expected_threads)

    def _run_internal_http(self):
        """run backend insecure http server

        A small inprocess server to syncronize info between gunicorn and the updater daemon.
        This HTTP server is not safe for exposing externally, but fine for IPC.
        """
        them = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(them.status()).encode())

            def log_error(self, format: str, *args: Any):
                them.log.info(format % args)

            def log_message(self, format: str, *args: Any):
                them.log.debug(format % args)

        self._internal_server = ThreadingHTTPServer(('0.0.0.0', 9999), Handler)
        self._internal_server.serve_forever()

    def _run_http(self):
        # Start a server for our http interface in a separate process
        my_env = os.environ.copy()
        proc = subprocess.Popen(["gunicorn", "assemblyline_v4_service.updater.app:app",
                                "--config=python:assemblyline_v4_service.updater.gunicorn_config"], env=my_env)
        while self.sleep(1):
            if proc.poll() is not None:
                break

        # If we have left the loop and the process is still alive, stop it.
        if proc.poll() is not None:
            proc.terminate()
            proc.wait()

    @staticmethod
    def config_hash(service: Service) -> int:
        if service is None:
            return 0
        return hash(json.dumps(service.update_config.as_primitives()))

    def _handle_source_update_event(self, data: list[str]):
        # Received an event regarding a change to source
        self.log.info(f'Triggered to update the following: {data}')
        self.do_source_update(self._service, specific_sources=data)
        self.local_update_flag.set()

    def _handle_signature_change_event(self, data: SignatureChange):
        self.local_update_flag.set()

    def _handle_service_change_event(self, data: ServiceChange):
        if data.operation == Operation.Modified:
            self._pull_settings()

    def _sync_settings(self):
        # Download the service object from datastore
        self._service = self.datastore.get_service_with_delta(SERVICE_NAME)

        while self.sleep(SERVICE_PULL_INTERVAL):
            self._pull_settings()

    def _pull_settings(self):
        # Download the service object from datastore
        self._service = self.datastore.get_service_with_delta(SERVICE_NAME)

        # If the update configuration for the service has changed, trigger an update
        if self.config_hash(self._service) != self.get_active_config_hash():
            self.source_update_flag.set()

    def push_status(self, state: str, message: str):
        # Push current state of updater with source
        self.log.debug(f"Pushing state for {self._current_source}: [{state}] {message}")
        self.update_data_hash.set(key=f'{self._current_source}.{SOURCE_STATUS_KEY}',
                                  value=dict(state=state, message=message, ts=now_as_iso()))

    def do_local_update(self) -> None:
        old_update_time = self.get_local_update_time()
        if not os.path.exists(UPDATER_DIR):
            os.makedirs(UPDATER_DIR)

        _, time_keeper = tempfile.mkstemp(prefix="time_keeper_", dir=UPDATER_DIR)
        if self._service.update_config.generates_signatures:
            output_directory = tempfile.mkdtemp(prefix="update_dir_", dir=UPDATER_DIR)

            self.log.info("Setup service account.")
            username = self.ensure_service_account()
            self.log.info("Create temporary API key.")
            with temporary_api_key(self.datastore, username) as api_key:
                self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}")
                al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=self.verify)

                # Check if new signatures have been added
                self.log.info("Check for new signatures.")
                if al_client.signature.update_available(
                        since=epoch_to_iso(old_update_time) or '', sig_type=self.updater_type)['update_available']:
                    self.log.info("An update is available for download from the datastore")

                    self.log.debug(f"{self.updater_type} update available since {epoch_to_iso(old_update_time) or ''}")

                    extracted_zip = False
                    attempt = 0

                    # Sometimes a zip file isn't always returned, will affect service's use of signature source. Patience..
                    while not extracted_zip and attempt < 5:
                        temp_zip_file = os.path.join(output_directory, 'temp.zip')
                        al_client.signature.download(
                            output=temp_zip_file,
                            query=f"type:{self.updater_type} AND (status:NOISY OR status:DEPLOYED)")

                        self.log.debug(f"Downloading update to {temp_zip_file}")
                        if os.path.exists(temp_zip_file) and os.path.getsize(temp_zip_file) > 0:
                            self.log.debug(
                                f"File type ({os.path.getsize(temp_zip_file)}B): {zip_ident(temp_zip_file, 'unknown')}")
                            try:
                                with ZipFile(temp_zip_file, 'r') as zip_f:
                                    zip_f.extractall(output_directory)
                                    extracted_zip = True
                                    self.log.info("Zip extracted.")
                            except BadZipFile:
                                attempt += 1
                                self.log.warning(f"[{attempt}/5] Bad zip. Trying again after 30s...")
                                time.sleep(30)
                            except Exception as e:
                                self.log.error(f'Problem while extracting signatures to disk: {e}')
                                break

                            os.remove(temp_zip_file)

                    if extracted_zip:
                        self.log.info("New ruleset successfully downloaded and ready to use")
                        self.serve_directory(output_directory, time_keeper)
                    else:
                        self.log.error("Signatures aren't saved to disk.")
                        shutil.rmtree(output_directory, ignore_errors=True)
                        if os.path.exists(time_keeper):
                            os.unlink(time_keeper)
                else:
                    self.log.info("No signature updates available.")
                    shutil.rmtree(output_directory, ignore_errors=True)
                    if os.path.exists(time_keeper):
                        os.unlink(time_keeper)
        else:
            output_directory = self.prepare_output_directory()
            self.serve_directory(output_directory, time_keeper)

    def do_source_update(self, service: Service, specific_sources: list[str] = []) -> None:
        self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}...")
        run_time = time.time()
        username = self.ensure_service_account()
        with temporary_api_key(self.datastore, username) as api_key:
            with tempfile.TemporaryDirectory() as update_dir:
                al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=self.verify)
                self.log.info("Connected!")

                # Parse updater configuration
                previous_hashes: dict[str, dict[str, str]] = self.get_source_extra()
                sources: dict[str, UpdateSource] = {_s['name']: _s for _s in service.update_config.sources}
                files_sha256: dict[str, dict[str, str]] = {}

                # Go through each source and download file
                for source_name, source_obj in sources.items():
                    # Set current source for pushing state to UI
                    self._current_source = source_name
                    old_update_time = self.get_source_update_time()
                    if specific_sources and source_name not in specific_sources:
                        # Parameter is used to determine if you want to update a specific source only
                        # Otherwise, assume we want to update all sources
                        continue

                    self.push_status("UPDATING", "Starting..")
                    source = source_obj.as_primitives()
                    uri: str = source['uri']
                    default_classification = source.get('default_classification', classification.UNRESTRICTED)
                    try:
                        self.push_status("UPDATING", "Pulling..")

                        # Pull sources from external locations (method depends on the URL)
                        files = git_clone_repo(source, old_update_time, self.default_pattern, self.log, update_dir)

                        # As not all services end with .git, we rely on the exception thrown by git_clone which sets (files is None)
                        # to determine if its a valid git repo or not.
                        if (files is None) and (not uri.endswith('.git')):
                            files = url_download(source, old_update_time, self.log, update_dir)

                        # Add to collection of sources for caching purposes
                        self.log.info(f"Found new {self.updater_type} rule files to process for {source_name}!")
                        validated_files = list()
                        for file, sha256 in files:
                            files_sha256.setdefault(source_name, {})
                            if previous_hashes.get(source_name, {}).get(file, None) != sha256 and self.is_valid(file):
                                files_sha256[source_name][file] = sha256
                                validated_files.append((file, sha256))

                        self.push_status("UPDATING", "Importing..")
                        # Import into Assemblyline
                        self.import_update(validated_files, al_client, source_name, default_classification)
                        self.push_status("DONE", "Signature(s) Imported.")

                    except SkipSource:
                        # This source hasn't changed, no need to re-import into Assemblyline
                        self.log.info(f'No new {self.updater_type} rule files to process for {source_name}')
                        if source_name in previous_hashes:
                            files_sha256[source_name] = previous_hashes[source_name]
                        self.push_status("DONE", "Skipped.")
                    except Exception as e:
                        self.push_status("ERROR", str(e))
                        continue

                    self.set_source_update_time(run_time)
                    self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()

    # Define to determine if file is a valid signature file
    def is_valid(self, file_path) -> bool:
        return True

    # Define how your source update gets imported into Assemblyline
    def import_update(self, files_sha256: List[Tuple[str, str]], client: Client, source_name: str,
                      default_classification=None):
        raise NotImplementedError()

    # Define how to prepare the output directory before being served, must return the path of the directory to serve.
    def prepare_output_directory(self) -> str:
        output_directory = tempfile.mkdtemp()
        shutil.copytree(self.latest_updates_dir, output_directory, dirs_exist_ok=True)
        return output_directory

    def _run_source_updates(self):
        # Wait until basic data is loaded
        while self._service is None and self.sleep(1):
            pass
        if not self._service:
            return
        self.log.info("Service info loaded")

        try:
            self.log.info("Checking for in cluster update cache")
            self.do_local_update()
            self._service_stage_hash.set(SERVICE_NAME, ServiceStage.Running)
            self.event_sender.send(SERVICE_NAME, {'operation': Operation.Modified, 'name': SERVICE_NAME})
        except Exception:
            self.log.exception('An error occurred loading cached update files. Continuing.')
        self.local_update_start.set()

        # Go into a loop running the update whenever triggered or its time to
        while self.running:
            # Stringify and hash the the current update configuration
            service = self._service
            update_interval = service.update_config.update_interval_seconds

            # Is it time to update yet?
            if time.time() - self.get_scheduled_update_time() < update_interval and not self.source_update_flag.is_set():
                self.source_update_flag.wait(60)
                continue

            if not self.running:
                return

            # With temp directory
            self.source_update_flag.clear()
            self.log.info('Calling update function...')
            # Run update function
            # noinspection PyBroadException
            try:
                self.do_source_update(service=service)
                self.set_scheduled_update_time(update_time=time.time())
            except Exception:
                self.log.exception('An error occurred running the update. Will retry...')
                self.source_update_flag.set()
                self.sleep(60)
                continue

    def serve_directory(self, new_directory: str, new_time: str):
        self.log.info("Update finished with new data.")
        new_tar = ''
        try:
            # Tar update directory
            _, new_tar = tempfile.mkstemp(prefix="signatures_", dir=UPDATER_DIR, suffix='.tar.bz2')
            tar_handle = tarfile.open(new_tar, 'w:bz2')
            tar_handle.add(new_directory, '/')
            tar_handle.close()

            # swap update directory with old one
            self._update_dir, new_directory = new_directory, self._update_dir
            self._update_tar, new_tar = new_tar, self._update_tar
            self._time_keeper, new_time = new_time, self._time_keeper
            self.log.info(f"Now serving: {self._update_dir} and {self._update_tar} ({self.get_local_update_time()})")
        finally:
            if new_tar and os.path.exists(new_tar):
                self.log.info(f"Remove old tar file: {new_tar}")
                time.sleep(3)
                os.unlink(new_tar)
            if new_directory and os.path.exists(new_directory):
                self.log.info(f"Remove old directory: {new_directory}")
                shutil.rmtree(new_directory, ignore_errors=True)
            if new_time and os.path.exists(new_time):
                self.log.info(f"Remove old time keeper file: {new_time}")
                os.unlink(new_time)

            # Cleanup old timekeepers/tars from unexpected termination(s) on persistent storage
            [os.unlink(os.path.join(UPDATER_DIR, file)) for file in os.listdir(UPDATER_DIR)
             if not self._update_tar.endswith(file) and file.startswith('signatures_')]
            [os.unlink(os.path.join(UPDATER_DIR, file)) for file in os.listdir(UPDATER_DIR)
             if not self._time_keeper.endswith(file) and file.startswith('time_keeper_')]

    def _run_local_updates(self):
        # Wait until basic data is loaded
        while self._service is None and self.sleep(1):
            pass
        if not self._service:
            return
        self.local_update_start.wait()

        # Go into a loop running the update whenever triggered or its time to
        while self.running:
            # Is it time to update yet?
            if not self.local_update_flag.is_set():
                self.local_update_flag.wait(60)
                continue

            if not self.running:
                return
            self.local_update_flag.clear()

            # With temp directory
            self.log.info('Updating local files...')
            # Run update function
            # noinspection PyBroadException
            try:
                self.do_local_update()
                if self._service_stage_hash.get(SERVICE_NAME) == ServiceStage.Update:
                    self._service_stage_hash.set(SERVICE_NAME, ServiceStage.Running)
                    self.event_sender.send(SERVICE_NAME, {'operation': Operation.Modified, 'name': SERVICE_NAME})
            except Exception:
                self.log.exception('An error occurred finding new local files. Will retry...')
                self.local_update_flag.set()
                self.sleep(60)
                continue

    def ensure_service_account(self):
        """Check that the update service account exists, if it doesn't, create it."""
        uname = 'update_service_account'
        user_obj = self.datastore.user.get_if_exists(uname)
        if user_obj and user_obj.roles:
            return uname

        user_data = User({
            "agrees_with_tos": "NOW",
            "classification": "RESTRICTED",
            "name": "Update Account",
            "password": get_password_hash(''.join(random.choices(string.ascii_letters, k=20))),
            "uname": uname,
            "type": ["custom"],
            "roles": UPDATER_API_ROLES
        })
        self.datastore.user.save(uname, user_data)
        self.datastore.user_settings.save(uname, UserSettings())
        return uname
