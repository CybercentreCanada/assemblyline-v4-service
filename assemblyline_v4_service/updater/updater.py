from __future__ import annotations
import shutil
from typing import Optional, Any
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

from assemblyline_core.server_base import ThreadedCoreBase, ServiceStage
from assemblyline.odm.models.service import Service
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.common.security import get_random_password, get_password_hash
from assemblyline.remote.datatypes.lock import Lock
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings


if typing.TYPE_CHECKING:
    import redis
    from assemblyline.odm.models.config import Config
    from assemblyline.datastore.helper import AssemblylineDatastore
    RedisType = redis.Redis[typing.Any]


SERVICE_PULL_INTERVAL = 60
SERVICE_NAME = os.getenv('AL_SERVICE_NAME', 'service')

CONFIG_HASH_KEY = 'config_hash'
SOURCE_UPDATE_TIME_KEY = 'update_time'
LOCAL_UPDATE_TIME_KEY = 'local_update_time'
SOURCE_EXTRA_KEY = 'source_extra'


@contextmanager
def temporary_api_key(ds: AssemblylineDatastore, user_name: str, permissions=('R', 'W')):
    """Creates a context where a temporary API key is available."""
    with Lock(f'user-{user_name}', timeout=10):
        name = ''.join(random.choices(string.ascii_lowercase, k=20))
        random_pass = get_random_password(length=48)
        user = ds.user.get(user_name)
        user.apikeys[name] = {
            "password": bcrypt.hash(random_pass),
            "acl": permissions
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
                 redis: RedisType = None, redis_persist: RedisType = None):
        super().__init__(f'assemblyline.{SERVICE_NAME}_updater', logger=logger, shutdown_timeout=shutdown_timeout,
                         config=config, datastore=datastore, redis=redis,
                         redis_persist=redis_persist)

        self.update_data_hash = Hash(f'service-updates-{SERVICE_NAME}', redis_persist)
        self._update_dir = None
        self._update_tar = None
        self._service: Optional[Service] = None

        # A event flag that gets set when an update should be run for
        # reasons other than it being the regular interval (eg, change in signatures)
        self.source_update_flag = threading.Event()
        self.local_update_flag = threading.Event()
        self._local_update_time: float = 0

        self._internal_server = None
        self.expected_threads = {
            'Sync Service Settings': self._sync_settings,
            'Outward HTTP Server': self._run_http,
            'Internal HTTP Server': self._run_internal_http,
            'Run source updates': self._run_source_updates,
            'Run local updates': self._run_local_updates,
        }

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

    def get_source_update_time(self) -> float:
        return self.update_data_hash.get(SOURCE_UPDATE_TIME_KEY) or 0

    def set_source_update_time(self, update_time: float):
        self.update_data_hash.set(SOURCE_UPDATE_TIME_KEY, update_time)

    def get_source_extra(self) -> dict[str, Any]:
        return self.update_data_hash.get(SOURCE_EXTRA_KEY) or {}

    def set_source_extra(self, extra_data: dict[str, Any]):
        self.update_data_hash.set(SOURCE_EXTRA_KEY, extra_data)

    def get_local_update_time(self) -> float:
        return self._local_update_time

    def set_local_update_time(self, update_time: float):
        self.local_update_time = update_time

    def status(self):
        return {
            'local_update_time': self.get_local_update_time(),
            'download_available': self._update_dir is not None,
            '_directory': self._update_dir,
            '_tar': self._update_tar,
        }

    def stop(self):
        super().stop()
        self.source_update_flag.set()
        self.local_update_flag.set()
        if self._internal_server:
            self._internal_server.shutdown()

    def try_run(self):
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
        proc = subprocess.Popen(["gunicorn", "assemblyline_v4_service.updater.app:app",
                                "--config=python:assemblyline_v4_service.updater.gunicorn_config"])
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

    def _sync_settings(self):
        # Download the service object from datastore
        self._service = self.datastore.get_service_with_delta(SERVICE_NAME)

        while self.sleep(SERVICE_PULL_INTERVAL):
            # Download the service object from datastore
            self._service = self.datastore.get_service_with_delta(SERVICE_NAME)

            # If the update configuration for the service has changed, trigger an update
            if self.config_hash(self._service) != self.get_active_config_hash():
                self.source_update_flag.set()

    def do_local_update(self) -> None:
        raise NotImplementedError()

    def do_source_update(self, service: Service) -> None:
        raise NotImplementedError()

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
        except Exception:
            self.log.exception('An error occurred loading cached update files. Continuing.')

        # Go into a loop running the update whenever triggered or its time to
        while self.running:
            # Stringify and hash the the current update configuration
            service = self._service
            update_interval = service.update_config.update_interval_seconds

            # Is it time to update yet?
            if time.time() - self.get_source_update_time() < update_interval and not self.source_update_flag.is_set():
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
            except Exception:
                self.log.exception('An error occurred running the update. Will retry...')
                self.source_update_flag.set()
                self.sleep(60)
                continue

    def serve_directory(self, new_directory: str):
        self.log.info("Update finished with new data.")
        new_tar = ''
        try:
            # Tar update directory
            _, new_tar = tempfile.mkstemp(suffix='.tar.bz2')
            tar_handle = tarfile.open(new_tar, 'w:bz2')
            tar_handle.add(new_directory, '/')
            tar_handle.close()

            # swap update directory with old one
            self._update_dir, new_directory = new_directory, self._update_dir
            self._update_tar, new_tar = new_tar, self._update_tar
            self.log.info(f"Now serving: {self._update_dir} and {self._update_tar}")
        finally:
            if new_tar and os.path.exists(new_tar):
                time.sleep(3)
                os.unlink(new_tar)
            if new_directory and os.path.exists(new_directory):
                shutil.rmtree(new_directory, ignore_errors=True)

    def _run_local_updates(self):
        # Wait until basic data is loaded
        while self._service is None and self.sleep(1):
            pass
        if not self._service:
            return

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
                self._service_stage_hash.set(SERVICE_NAME, ServiceStage.Running)
            except Exception:
                self.log.exception('An error occurred finding new local files. Will retry...')
                self.local_update_flag.set()
                self.sleep(60)
                continue

    def ensure_service_account(self):
        """Check that the update service account exists, if it doesn't, create it."""
        uname = 'update_service_account'

        if self.datastore.user.get_if_exists(uname):
            return uname

        user_data = User({
            "agrees_with_tos": "NOW",
            "classification": "RESTRICTED",
            "name": "Update Account",
            "password": get_password_hash(''.join(random.choices(string.ascii_letters, k=20))),
            "uname": uname,
            "type": ["signature_importer"]
        })
        self.datastore.user.save(uname, user_data)
        self.datastore.user_settings.save(uname, UserSettings())
        return uname
