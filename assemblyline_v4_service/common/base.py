from __future__ import annotations

import logging
import os
import requests
import shutil
import tarfile
import tempfile
import time
from typing import Dict, Optional

from assemblyline.common import exceptions, log, version
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.api import ServiceAPI
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task

LOG_LEVEL = logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO"))


class ServiceBase:
    def __init__(self, config: Optional[Dict] = None) -> None:
        # Load the service attributes from the service manifest
        self.service_attributes = helper.get_service_attributes()

        # Start with default service parameters and override with anything provided
        self.config = self.service_attributes.config
        if config:
            self.config.update(config)

        # Initialize logging for the service
        log.init_logging(f'{self.service_attributes.name}', log_level=LOG_LEVEL)
        self.log = logging.getLogger(f'assemblyline.service.{self.service_attributes.name.lower()}')

        # Replace warning/error methods with our own patched version
        self._log_warning = self.log.warning
        self._log_error = self.log.error

        self.log.warning = self._warning
        self.log.error = self._error

        self._task = None

        self._working_directory = None
        self.dependencies = self._get_dependencies_info()

        # Updater-related
        self.rules_directory: str = None
        self.rules_list: list = []
        self.update_time: int = None
        self.rules_hash: str = None

    def _get_dependencies_info(self) -> None:
        dependencies = {}
        dep_names = [e.split('_key')[0] for e in os.environ.keys() if e.endswith('_key')]
        for name in dep_names:
            try:
                dependencies[name] = {part: os.environ[f'{name}_{part}'] for part in ['host', 'port', 'key']}
            except KeyError:
                pass
        return dependencies

    def _cleanup(self) -> None:
        self._task = None
        self._working_directory = None
        if self.dependencies.get('updates', None):
            try:
                self._update_rules()
            except Exception as e:
                raise Exception(f"Something went wrong while trying to load {self.name} rules: {str(e)}")

    def _handle_execute_failure(self, exception, stack_info) -> None:
        # Clear the result, in case it caused the problem
        self._task.result = None

        # Clear the extracted and supplementary files
        self._task.clear_extracted()
        self._task.clear_supplementary()

        if isinstance(exception, exceptions.RecoverableError):
            self.log.info(f"Recoverable Service Error "
                          f"({self._task.sid}/{self._task.sha256}) {exception}: {stack_info}")
            self._task.save_error(stack_info, recoverable=True)
        else:
            self.log.error(f"Nonrecoverable Service Error "
                           f"({self._task.sid}/{self._task.sha256}) {exception}: {stack_info}")
            self._task.save_error(stack_info, recoverable=False)

    def _success(self) -> None:
        self._task.success()

    def _warning(self, msg: str, *args, **kwargs) -> None:
        if self._task:
            msg = f"({self._task.sid}/{self._task.sha256}): {msg}"
        self._log_warning(msg, *args, **kwargs)

    def _error(self, msg: str, *args, **kwargs) -> None:
        if self._task:
            msg = f"({self._task.sid}/{self._task.sha256}): {msg}"
        self._log_error(msg, *args, **kwargs)

    def get_api_interface(self):
        return ServiceAPI(self.service_attributes, self.log)

    def execute(self, request: ServiceRequest) -> None:
        raise NotImplementedError("execute() function not implemented")

    def get_service_version(self) -> str:
        fw_version = f"{version.FRAMEWORK_VERSION}.{version.SYSTEM_VERSION}."
        if self.service_attributes.version.startswith(fw_version):
            return self.service_attributes.version
        else:
            return f"{fw_version}{self.service_attributes.version}"

    # noinspection PyMethodMayBeStatic
    def get_tool_version(self) -> Optional[str]:
        return None

    def handle_task(self, task: ServiceTask) -> None:
        try:
            self._task = Task(task)
            self.log.info(f"Starting task: {self._task.sid}/{self._task.sha256} ({self._task.type})")
            self._task.start(self.service_attributes.default_result_classification,
                             self.service_attributes.version, self.get_tool_version())

            request = ServiceRequest(self._task)
            self.execute(request)

            self._success()
        except Exception as ex:
            self._handle_execute_failure(ex, exceptions.get_stacktrace_info(ex))
        finally:
            self._cleanup()

    def start(self) -> None:
        """
        Called at worker start.

        :return:
        """
        pass

    def start_service(self) -> None:
        self.log.info(f"Starting service: {self.service_attributes.name}")

        if self.dependencies.get('updates', None):
            try:
                self._update_rules()
            except Exception as e:
                raise Exception(f"Something went wrong while trying to load {self.name} rules: {str(e)}")

        self.start()

    def stop(self) -> None:
        """
        Called at worker stop.

        :return:
        """
        pass

    def stop_service(self) -> None:
        # Perform common stop routines and then invoke the child's stop().
        self.log.info(f"Stopping service: {self.service_attributes.name}")
        self.stop()

    @property
    def working_directory(self):
        temp_dir = os.path.join(tempfile.gettempdir(), 'working_directory')
        if not os.path.isdir(temp_dir):
            os.makedirs(temp_dir)
        if self._working_directory is None:
            self._working_directory = tempfile.mkdtemp(dir=temp_dir)
        return self._working_directory

    # Only relevant for services using updaters (reserving 'updates' as the defacto container name)
    def _download_rules(self):
        url_base = f"http://{self.dependencies['updates']['host']}:{self.dependencies['updates']['port']}/"
        headers = {
            'X_APIKEY': self.dependencies['updates']['key']
        }

        # Check if there are new
        while True:
            resp = requests.get(url_base + 'status')
            resp.raise_for_status()
            status = resp.json()
            if self.update_time is not None and self.update_time >= status['local_update_time']:
                return False
            if status['download_available']:
                break
            self.log.warning('Waiting on update server availability...')
            time.sleep(10)

        # Download the current update
        temp_directory = tempfile.mkdtemp()
        buffer_handle, buffer_name = tempfile.mkstemp()
        try:
            with os.fdopen(buffer_handle, 'wb') as buffer:
                resp = requests.get(url_base + 'tar', headers=headers)
                resp.raise_for_status()
                for chunk in resp.iter_content(chunk_size=1024):
                    buffer.write(chunk)

            tar_handle = tarfile.open(buffer_name)
            tar_handle.extractall(temp_directory)
            self.update_time = status['local_update_time']
            self.rules_directory, temp_directory = temp_directory, self.rules_directory
            return True
        finally:
            os.unlink(buffer_name)
            if temp_directory:
                shutil.rmtree(temp_directory, ignore_errors=True)

    def _update_rules(self):
        if self._download_rules() and self._load_rules():
            self.rules_hash = self._get_rules_hash()
            self._load_rules()

    def _get_rules_hash(self) -> str:
        raise NotImplementedError()

    def _load_rules(self) -> bool:
        raise NotImplementedError
