import hashlib
import shutil
import tarfile
import tempfile
from typing import Optional, Any, Dict
import time
import json
import threading
import os

from assemblyline.common import forge
from assemblyline.cachestore import CacheStore
from assemblyline.common.importing import load_module_by_path
from assemblyline.odm.models.service import Service
from assemblyline.remote.datatypes import get_client
from assemblyline.remote.datatypes.hash import Hash

from flask import Flask


SERVICE_PULL_INTERVAL = 5 * 60
UPDATE_FUNCTION_PATH = os.getenv('UPDATE_FUNCTION_PATH')
CHECK_FUNCTION_PATH = os.getenv('CHECK_FUNCTION_PATH')
SERVICE_NAME = os.getenv('SERVICE_NAME')


class BackgroundUpdateApp(Flask):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__update_dir: Optional[str] = None
        self.__update_tar: Optional[str] = None
        self.__service: Optional[Service] = None

        self.__update_data_hash: Optional[Hash] = None
        self.__update_data: Optional[Dict] = None

    def update_dir(self):
        return self.__update_dir

    def update_tar(self):
        return self.__update_tar

    @property
    def service(self):
        return self.__service

    def run(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        debug: Optional[bool] = None,
        load_dotenv: bool = True,
        **options: Any,
    ) -> None:
        # Load information about the service
        # self.__service_manifest = helper.get_service_manifest()
        config = forge.get_config()
        redis_persist = get_client(
            host=config.core.redis.persistent.host,
            port=config.core.redis.persistent.port,
            private=False,
        )
        self.__update_data_hash = Hash('service-updates', redis_persist)

        # Start the thread that looks for system settings
        threading.Thread(target=self._sync_settings, daemon=True).start()

        # Start the thread that runs updates
        threading.Thread(target=self._run_updates, daemon=True).start()

        # Launch the flask application normally
        super().run(host=host, port=port, debug=debug, load_dotenv=load_dotenv, **options)

    def _sync_settings(self):
        datastore = forge.get_datastore()
        while True:
            # Download information about the last update
            self.__update_data = self.__update_data_hash.get(SERVICE_NAME) or {}

            # Download the service object from datastore
            self.__service = datastore.get_service_with_delta(SERVICE_NAME)

            # Wait
            time.sleep(SERVICE_PULL_INTERVAL)

    def _run_updates(self):
        # Wait until basic data is loaded
        while True:
            if self.service is not None:
                break
            time.sleep(5)

        with CacheStore(f'updates-{self.service.name}') as storage:
            # Check for existing update hash
            # noinspection PyBroadException
            try:
                last_hash = self.__update_data.get('hash', None)
                compressed = None
                if last_hash is not None and storage.exists(last_hash):
                    # If found download and extract update directory
                    _, compressed = tempfile.mkstemp()
                    storage.download(last_hash, compressed)
                    directory = tempfile.mkdtemp()
                    tar_handle = tarfile.open(compressed, 'r')
                    tar_handle.extractall(directory)

                    # Put update directory into place
                    self.__update_dir = directory
                    self.__update_tar = compressed
            except Exception:
                self.logger.exception('An error occurred reading old update files. Continuing.')
                if compressed:
                    os.unlink(compressed)

            update_function = load_module_by_path(UPDATE_FUNCTION_PATH)
            while True:

                # Stringify and hash the the current update configuration
                config_hash = hash(json.dumps(self.__service.update_config.as_primitives()))
                hash_out_of_date = config_hash != self.__update_data.get('config_hash')
                update_interval = self.service.update_config.update_interval_seconds

                # Is it time to update yet?
                if time.time() - self.__update_data.get('update_time', 0) < update_interval and not hash_out_of_date:
                    time.sleep(60)
                    continue

                # With temp directory
                new_directory = tempfile.mkdtemp()
                try:
                    # Run update function
                    # noinspection PyBroadException
                    try:
                        expect_changes = update_function(output_directory=new_directory,
                                                         old_hash=self.__update_data.get('hash', None),
                                                         config_hash=self.__update_data.get('config_hash', None),
                                                         last_update_time=self.__update_data.get('update_time', None))
                    except Exception:
                        self.logger.exception('An error occurred running the update. Will retry...')
                        time.sleep(60)
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
                        if self.__update_data.get('hash') == new_hash:
                            storage.touch(new_hash, expiry_duration)
                            continue

                        # upload tar file
                        storage.upload(new_tar, new_hash, ttl=expiry_duration)

                        # set new update time/hash data in redis and locally
                        self.__update_data['hash'] = new_hash
                        self.__update_data['config_hash'] = config_hash
                        self.__update_data['update_time'] = time.time()
                        self.__update_data_hash.set(self.service.name, self.__update_data)

                        # swap update directory with old one
                        self.__update_dir, new_directory = new_directory, self.__update_dir
                        self.__update_tar, new_tar = new_tar, self.__update_tar
                    else:
                        # set new update time/hash data in redis and locally
                        self.__update_data['config_hash'] = config_hash
                        self.__update_data['update_time'] = time.time()
                        self.__update_data_hash.set(self.service.name, self.__update_data)

                finally:
                    if new_directory:
                        shutil.rmtree(new_directory)
                    if new_tar:
                        os.unlink(new_tar)

    def pre_download_check(self):
        if not UPDATE_FUNCTION_PATH:
            return
        # noinspection PyBroadException
        try:
            check_function = load_module_by_path(UPDATE_FUNCTION_PATH)
            check_function(directory=self.update_dir(),
                           old_hash=self.__update_data.get('hash', None),
                           config_hash=self.__update_data.get('config_hash', None),
                           last_update_time=self.__update_data.get('update_time', None))
        except Exception:
            self.logger.exception('An error occurred checking for updates.')
            return
