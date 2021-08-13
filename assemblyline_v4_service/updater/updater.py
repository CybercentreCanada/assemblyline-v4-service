from multiprocessing.managers import BaseManager
from typing import Dict, Optional
import typing
import os
import logging
import time
import json
import tempfile
import hashlib
import tarfile
import shutil
import threading
import subprocess

from assemblyline.common.importing import load_module_by_path
from assemblyline.cachestore import CacheStore
from assemblyline.common.server_base import ThreadedCoreBase
from assemblyline.odm.models.service import Service
from assemblyline.remote.datatypes.hash import Hash


SERVICE_PULL_INTERVAL = 60
UPDATE_FUNCTION_PATH = os.getenv('UPDATE_FUNCTION_PATH', None)
CHECK_FUNCTION_PATH = os.getenv('CHECK_FUNCTION_PATH', None)
SERVICE_NAME = os.getenv('AL_SERVICE_NAME', 'service')

MANAGER_HOST = ''
MANAGER_PORT = 20000
MANAGER_KEY = b'update-container'
EXPORTED_METHODS = ('trigger_update', 'update_directory', 'update_tar', 'status')


# Register the interface by name
class UpdaterRPC(BaseManager):
    pass
UpdaterRPC.register('updater', exposed=EXPORTED_METHODS)


class ServiceUpdater(ThreadedCoreBase):
    def __init__(self, logger: logging.Logger=None, 
                 shutdown_timeout: float=None, config=None, datastore=None,
                 redis=None, redis_persist=None):
        super().__init__(SERVICE_NAME + '-updater', logger=logger, shutdown_timeout=shutdown_timeout, 
                         config=config, datastore=datastore, redis=redis, 
                         redis_persist=redis_persist)

        self.update_data_hash = Hash('service-updates', redis_persist)
        self._update_dir = None
        self._update_tar = None
        self._service: Optional[Service] = None

        # Import functions now that the logger is initialized
        if UPDATE_FUNCTION_PATH is None:
            self.log.error("environment variable UPDATE_FUNCTION_PATH [undefined] "
                           "must be set to python path for update function")
            exit(1)

        self._update_function = load_module_by_path(UPDATE_FUNCTION_PATH)
        if self._update_function is None:
            self.log.error(f"environment variable UPDATE_FUNCTION_PATH [{UPDATE_FUNCTION_PATH}] "
                            "must be set to python path for update function")
            exit(1)            

        # A event flag that gets set when an update should be run for 
        # reasons other than it being the regular interval (eg, change in signatures)
        self.update_flag = threading.Event()

        # On the server side, register the api methods the http server can use including
        # their function.
        UpdaterRPC.register('updater', callable=lambda:self, exposed=EXPORTED_METHODS)
        self.rpc_manager = UpdaterRPC(address=(MANAGER_HOST, MANAGER_PORT), authkey=MANAGER_KEY)

    def trigger_update(self):
        self.update_flag.set()

    def update_directory(self):
        return self._update_dir

    def update_tar(self):
        return self._update_tar        

    def update_data(self) -> Dict:
        return typing.cast(Dict, self.update_data_hash.get(SERVICE_NAME) or {})

    def status(self):
        data = self.update_data()
        data['update_running'] = self.update_flag.is_set()
        data['update_available'] = self._update_dir is not None
        return data

    def start(self):
        self.rpc_manager.start()
        super().start()

    def stop(self):
        super().stop()
        self.update_flag.set()
        self.rpc_manager.shutdown()

    def try_run(self):
        self.maintain_threads({
            'Sync Service Settings': self._sync_settings,
            'HTTP Server': self._run_http
        })

    def _run_http(self):
        # Start a server for our http interface in a separate process
        proc = subprocess.Popen(["gunicorn", "assemblyline_v4_service.updater.app:app", "--config=python:assemblyline_v4_service.updater.gunicorn_config"])
        while self.sleep(1):
            if proc.poll() is not None:
                break

        # If we have left the loop and the process is still alive, stop it.
        if proc.poll() is not None:
            proc.terminate()
            proc.wait()
        
    def config_hash(self):
        if self._service is None:
            return None
        return hash(json.dumps(self._service.update_config.as_primitives()))

    def _sync_settings(self):
        while self._service is None or self.sleep(SERVICE_PULL_INTERVAL):
            # Download the service object from datastore
            self._service = typing.cast(Service, self.datastore.get_service_with_delta(SERVICE_NAME))

            # If the update configuration for the service has changed, trigger an update
            stored_data = self.update_data()
            if self.config_hash() != stored_data.get('config_hash'):
                self.trigger_update()


    def _run_updates(self):
        # Wait until basic data is loaded
        while self._service is None and self.sleep(1): ...
        if not self._service:
            return

        # Connect to the filestore
        with CacheStore(f'updates-{self._service.name}') as storage:
            # Try to load any existing update.
            compressed = None
            try:
                last_hash = self.update_data.get('hash', None)
                if last_hash is not None and storage.exists(last_hash):
                    # If found download and extract update directory
                    _, compressed = tempfile.mkstemp()
                    storage.download(last_hash, compressed)
                    directory = tempfile.mkdtemp()
                    tar_handle = tarfile.open(compressed, 'r')
                    tar_handle.extractall(directory)

                    # Put update directory into place
                    self._update_dir = directory
                    self._update_tar = compressed
            except Exception:
                self.log.exception('An error occurred reading old update files. Continuing.')
                if compressed:
                    os.unlink(compressed)

            # Go into a loop running the update whenever triggered or its time to
            while self.running:
                # Stringify and hash the the current update configuration
                service = self._service
                running_config_hash = hash(json.dumps(service.update_config.as_primitives()))
                update_data = self.update_data()
                update_interval = service.update_config.update_interval_seconds

                # Is it time to update yet?
                if time.time() - update_data.get('update_time', 0) < update_interval and not self.update_flag.is_set():
                    self.update_flag.wait(60)
                    continue

                self.update_flag.set()
                if not self.running:
                    return

                # With temp directory
                new_directory = tempfile.mkdtemp()
                new_tar = None
                try:
                    old_data = self.update_data()
                    # Run update function
                    # noinspection PyBroadException
                    try:
                        expect_changes = self._update_function(
                            output_directory=new_directory,
                            service=service,
                            old_hash=old_data.get('hash', None),
                            old_config_hash=old_data.get('config_hash', None),
                            new_config_hash=running_config_hash,
                            old_update_time=old_data.get('update_time', None)
                        )
                    except Exception:
                        self.log.exception('An error occurred running the update. Will retry...')
                        self.sleep(60)
                        continue

                    if expect_changes:
                        # Tar update directory
                        raw_file_handle, new_tar = tempfile.mkstemp(suffix='.tar.bz2')
                        tar_handle = tarfile.open(new_tar, 'w:bz2')
                        tar_handle.add(new_directory, '/')
                        tar_handle.close()

                        # Calculate hash
                        hash_calculator = hashlib.sha256()
                        file_handle = os.fdopen(raw_file_handle, 'rb')
                        file_handle.seek(0)
                        while True:
                            chunk = file_handle.read(2 ** 12)
                            if not chunk:
                                break
                            hash_calculator.update(chunk)
                        new_hash = hash_calculator.hexdigest()

                        # Check if hash is the same as last time
                        expiry_duration = update_interval * 5
                        if old_data.get('hash') == new_hash:
                            storage.touch(new_hash, expiry_duration)
                            continue

                        # upload tar file
                        storage.upload(new_tar, new_hash, ttl=expiry_duration)

                        # set new update time/hash data in redis and locally
                        self.update_data_hash.set(service.name, {
                            'hash': new_hash,
                            'config_hash': running_config_hash,
                            'update_time': time.time()
                        })

                        # swap update directory with old one
                        self._update_dir, new_directory = new_directory, self._update_dir
                        self._update_tar, new_tar = new_tar, self._update_tar
                    else:
                        # set new update time/hash data in redis
                        self.update_data_hash.set(service.name, {
                            'hash': old_data['hash'],
                            'config_hash': running_config_hash,
                            'update_time': time.time()
                        })

                finally:
                    self.update_flag.clear()
                    if new_directory:
                        shutil.rmtree(new_directory)
                    if new_tar:
                        os.unlink(new_tar)

    # def pre_download_check(self):
    #     if not UPDATE_FUNCTION_PATH:
    #         return
    #     # noinspection PyBroadException
    #     try:
    #         check_function = load_module_by_path(UPDATE_FUNCTION_PATH)
    #         check_function(directory=self.update_dir(),
    #                        old_hash=self.update_data.get('hash', None),
    #                        config_hash=self.update_data.get('config_hash', None),
    #                        last_update_time=self.update_data.get('update_time', None))
    #     except Exception:
    #         self.logger.exception('An error occurred checking for updates.')
    #         return

