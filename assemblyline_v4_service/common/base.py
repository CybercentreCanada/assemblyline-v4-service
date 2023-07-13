from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tarfile
import tempfile
import time
import warnings
from pathlib import Path
from typing import Dict, Optional

import requests
from assemblyline.common import exceptions, log, version
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.api import PrivilegedServiceAPI, ServiceAPI
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task

# Ignore all other warnings that a service's libraries can generate
warnings.filterwarnings("ignore")

LOG_LEVEL = logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO"))
UPDATES_DIR = os.environ.get('UPDATES_DIR', '/updates')
UPDATES_CA = os.environ.get('UPDATES_CA', '/etc/assemblyline/ssl/al_root-ca.crt')
PRIVILEGED = os.environ.get('PRIVILEGED', 'false') == 'true'
MIN_SECONDS_BETWEEN_UPDATES = float(os.environ.get('MIN_SECONDS_BETWEEN_UPDATES', '10.0'))
SIGNATURES_META_FILENAME = "signatures_meta.json"

RECOVERABLE_RE_MSG = [
    "cannot schedule new futures after interpreter shutdown",
    "can't register atexit after shutdown",
    "cannot schedule new futures after shutdown"
]


def is_recoverable_runtime_error(error):
    return any(msg in str(error) for msg in RECOVERABLE_RE_MSG)


class ServiceBase:
    def __init__(self, config: Optional[Dict] = None) -> None:
        # Load the service attributes from the service manifest
        self.service_attributes = helper.get_service_attributes()

        # Start with default service parameters and override with anything provided
        self.config = self.service_attributes.config
        if config:
            self.config.update(config)

        self.name = self.service_attributes.name.lower()
        # Initialize logging for the service
        log.init_logging(f'{self.service_attributes.name}', log_level=LOG_LEVEL)
        self.log = logging.getLogger(f'assemblyline.service.{self.name}')

        # Replace warning/error methods with our own patched version
        self._log_warning = self.log.warning
        self._log_error = self.log.error

        self.log.warning = self._warning
        self.log.error = self._error

        self._task = None

        self._working_directory = None

        # Initialize interface for interacting with system safelist
        self._api_interface = None

        self.dependencies = self._get_dependencies_info()
        self.ontology = OntologyHelper(self.log, self.service_attributes.name)

        # Updater-related
        self.rules_directory: str = None
        self.rules_list: list = []
        self.update_time: int = None
        self.update_hash: str = None
        self.update_check_time: float = 0.0
        self.rules_hash: str = None
        self.signatures_meta: dict = {}

    @property
    def api_interface(self):
        return self.get_api_interface()

    def _get_dependencies_info(self) -> Dict[str, Dict[str, str]]:
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
                self._download_rules()
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
        if not self._api_interface:
            if PRIVILEGED:
                self._api_interface = PrivilegedServiceAPI(self.log)
            else:
                self._api_interface = ServiceAPI(self.service_attributes, self.log)

        return self._api_interface

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
        return self.rules_hash

    def handle_task(self, task: ServiceTask) -> None:
        try:
            self._task = Task(task)
            self.log.info(f"[{self._task.sid}] Starting task for file: {self._task.sha256} ({self._task.type})")
            self._task.start(self.service_attributes.default_result_classification,
                             self.service_attributes.version, self.get_tool_version())
            self.ontology.reset()
            request = ServiceRequest(self._task)
            self.execute(request)
            self.ontology._attach_ontology(request, self.working_directory)
            self._success()
        except RuntimeError as re:
            if is_recoverable_runtime_error(re):
                new_ex = exceptions.RecoverableError("Service trying to use a threadpool during shutdown")
                self._handle_execute_failure(new_ex, exceptions.get_stacktrace_info(re))
            else:
                self._handle_execute_failure(re, exceptions.get_stacktrace_info(re))
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
        self.log.info(f"Starting service: {self.service_attributes.name} ({self.service_attributes.version})")

        if self.dependencies.get('updates', None):
            # Start with a clean update dir
            if os.path.exists(UPDATES_DIR):
                for files in os.scandir(UPDATES_DIR):
                    path = os.path.join(UPDATES_DIR, files)
                    try:
                        shutil.rmtree(path)
                    except OSError:
                        os.remove(path)

            try:
                self._download_rules()
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
        # If no working directory is assigned
        if not self._working_directory:
            if self._task:
                # Then use the working directory provided by the task
                self._working_directory = self._task.working_directory
            else:
                # Or create a new working directory
                temp_dir = os.path.join(os.environ.get('TASKING_DIR', tempfile.gettempdir()), 'working_directory')
                if not os.path.isdir(temp_dir):
                    os.makedirs(temp_dir)
                self._working_directory = tempfile.mkdtemp(dir=temp_dir)

        return self._working_directory

    # Only relevant for services using updaters (reserving 'updates' as the defacto container name)
    def _download_rules(self):
        # check if we just tried to download rules to reduce traffic
        if time.time() - self.update_check_time < MIN_SECONDS_BETWEEN_UPDATES:
            return
        self.update_check_time = time.time()

        # Resolve the update target
        scheme, verify = 'http', None
        if os.path.exists(UPDATES_CA):
            scheme, verify = 'https', UPDATES_CA
        url_base = f"{scheme}://{self.dependencies['updates']['host']}:{self.dependencies['updates']['port']}/"
        headers = {
            'X_APIKEY': self.dependencies['updates']['key']
        }

        # Check if there are new signatures
        retries = 0
        while True:
            resp = requests.get(url_base + 'status', verify=verify)
            resp.raise_for_status()
            status = resp.json()
            if self.update_time is not None and self.update_time >= status['local_update_time'] and self.update_hash == status['local_update_hash']:
                self.log.info(f"There are no new signatures. ({self.update_time} >= {status['local_update_time']})")
                return
            if status['download_available']:
                self.log.info("A signature update is available, downloading new signatures...")
                break
            self.log.warning('Waiting on update server availability...')
            time.sleep(min(5**retries, 30))
            retries += 1

        # Dedicated directory for updates
        if not os.path.exists(UPDATES_DIR):
            os.mkdir(UPDATES_DIR)

        # Download the current update
        temp_directory = tempfile.mkdtemp(dir=UPDATES_DIR)
        buffer_handle, buffer_name = tempfile.mkstemp()

        old_rules_list = self.rules_list
        try:
            with os.fdopen(buffer_handle, 'wb') as buffer:
                resp = requests.get(url_base + 'tar', headers=headers, verify=verify)
                resp.raise_for_status()
                for chunk in resp.iter_content(chunk_size=1024):
                    buffer.write(chunk)

            tar_handle = tarfile.open(buffer_name)
            tar_handle.extractall(temp_directory)
            self.update_time = status['local_update_time']
            self.update_hash = status['local_update_hash']
            self.rules_directory, temp_directory = temp_directory, self.rules_directory
            # Try to load the rules into the service before declaring we're using these rules moving forward
            temp_hash = self._gen_rules_hash()
            self._clear_rules()
            self._load_rules()
            self.rules_hash = temp_hash
        except Exception as e:
            # Should something happen, we should revert to the old set and log the exception
            self.log.error(f'Error occurred while updating signatures: {e}. Reverting to the former signature set.')
            self.rules_directory, temp_directory = temp_directory, self.rules_directory
            # Clear rules that was added from the new set and reload old set
            self.rules_list = old_rules_list
            self._clear_rules()
            self._load_rules()
        finally:
            os.unlink(buffer_name)
            if temp_directory:
                self.log.info(f'Removing temp directory: {temp_directory}')
                shutil.rmtree(temp_directory, ignore_errors=True)

    # Generate the rules_hash and init rules_list based on the raw files in the rules_directory from updater
    def _gen_rules_hash(self) -> str:
        self.rules_list = [str(f) for f in Path(self.rules_directory).rglob("*") if os.path.isfile(str(f))]
        signatures_meta_path = os.path.join(self.rules_directory, SIGNATURES_META_FILENAME)
        if signatures_meta_path in self.rules_list:
            self.rules_list.remove(signatures_meta_path)
            self.signatures_meta = json.loads(open(signatures_meta_path, 'r').read())

        all_sha256s = [get_sha256_for_file(f) for f in self.rules_list]

        if len(all_sha256s) == 1:
            return all_sha256s[0][:7]

        return hashlib.sha256(' '.join(sorted(all_sha256s)).encode('utf-8')).hexdigest()[:7]

    # Clear all rules from the service; should be followed by a _load_rule()
    def _clear_rules(self) -> None:
        pass

    # Use the rules_list to setup rules-use for the service
    def _load_rules(self) -> None:
        raise NotImplementedError
