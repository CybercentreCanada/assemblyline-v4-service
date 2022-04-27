import copy
import json
import os
import shutil
import tempfile
import yaml

from json import JSONDecodeError
from io import BytesIO

from assemblyline.common import forge
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.importing import load_module_by_path
from assemblyline.common.metrics import MetricsFactory
from assemblyline.common.str_utils import StringTable
from assemblyline.common.version import FRAMEWORK_VERSION, SYSTEM_VERSION, BUILD_MINOR
from assemblyline.filestore import FileStoreException
from assemblyline.remote.datatypes import get_client
from assemblyline.odm.messages.service_heartbeat import Metrics
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_core.tasking_client import TaskingClient
from assemblyline_core.server_base import ServerBase
from assemblyline_v4_service.common.base import LOG_LEVEL, is_recoverable_runtime_error

SERVICE_PATH = os.environ['SERVICE_PATH']
SERVICE_TAG = os.environ.get("SERVICE_TAG", f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.{BUILD_MINOR}.dev0").encode("utf-8")
SERVICE_MANIFEST = os.path.join(os.getcwd(), os.environ.get('MANIFEST_FOLDER', ''), 'service_manifest.yml')
REGISTER_ONLY = os.environ.get('REGISTER_ONLY', 'False').lower() == 'true'

SERVICE_NAME = SERVICE_PATH.split(".")[-1].lower()
SHUTDOWN_SECONDS_LIMIT = 10
TASK_REQUEST_TIMEOUT = 30

STATUSES = StringTable('STATUSES', [
    ('INITIALIZING', 0),
    ('WAITING_FOR_TASK', 1),
    ('DOWNLOADING_FILE', 2),
    ('PROCESSING', 3),
    ('RESULT_FOUND', 4),
    ('ERROR_FOUND', 5),
    ('STOPPING', 6),
    ('FILE_NOT_FOUND', 7),
])


class RunPrivilegedService(ServerBase):
    def __init__(self, shutdown_timeout: int = SHUTDOWN_SECONDS_LIMIT):
        super(RunPrivilegedService, self).__init__(
            f'assemblyline.service.{SERVICE_NAME}', shutdown_timeout=shutdown_timeout)

        self.client_id = os.environ.get('HOSTNAME', 'dev-service')

        self.redis = get_client(
            host=self.config.core.redis.nonpersistent.host,
            port=self.config.core.redis.nonpersistent.port,
            private=False,
        )

        self.redis_persist = get_client(
            host=self.config.core.redis.persistent.host,
            port=self.config.core.redis.persistent.port,
            private=False,
        )

        self.tasking_client = TaskingClient(redis=self.redis, redis_persist=self.redis_persist)
        self.tasking_dir = os.environ.get('TASKING_DIR', tempfile.gettempdir())

        self.filestore = forge.get_filestore()

        self.service = None
        self.service_config = {}
        self.service_name = None
        self.service_tool_version = None

        self.status = STATUSES.INITIALIZING
        self.metric_factory = None

        self.log.setLevel(LOG_LEVEL)

    def _load_manifest(self):
        bio = BytesIO()
        with open(SERVICE_MANIFEST, "rb") as srv_manifest:
            for line in srv_manifest.readlines():
                bio.write(line.replace(b"$SERVICE_TAG", SERVICE_TAG))
            bio.flush()
        bio.seek(0)

        return yaml.safe_load(bio)

    def _cleanup_working_directory(self):
        # Make the tasking dir if it does not exists
        if not os.path.exists(self.tasking_dir):
            os.makedirs(self.tasking_dir)

        for file in os.listdir(self.tasking_dir):
            file_path = os.path.join(self.tasking_dir, file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception:
                pass

    def try_run(self):
        self.status = STATUSES.INITIALIZING

        # Try to load service class
        try:
            service_class = load_module_by_path(SERVICE_PATH)
        except Exception:
            self.log.error("Could not find service in path.")
            raise

        # Load on-disk manifest for bootstrap/registration
        service_manifest = self._load_manifest()

        # Register the service
        registration = self.tasking_client.register_service(service_manifest)

        # Are we just registering?
        if not registration['keep_alive'] or REGISTER_ONLY:
            self.status = STATUSES.STOPPING
            self.stop()
            return

        # Instantiate the service based of the registration results
        self.service_config = registration.get('service_config', {})
        self.service = service_class(config=self.service_config.get('config'))
        self.service_name = self.service_config['name']
        self.service_tool_version = self.service.get_tool_version()
        self.metric_factory = MetricsFactory('service', Metrics, name=self.service_name,
                                             export_zero=False, redis=self.redis)
        file_required = self.service_config.get('file_required', True)

        # Start the service
        self.service.start_service()

        while self.running:
            # Cleanup the working directory
            self._cleanup_working_directory()

            # Get a task
            self.status = STATUSES.WAITING_FOR_TASK
            task, _ = self.tasking_client.get_task(self.client_id, self.service_name, self.service_config['version'],
                                                   self.service_tool_version, self.metric_factory)

            if not task:
                continue

            # Load Task
            try:
                # Inspect task to ensure submission parameters are given, add defaults where necessary
                params = {x['name']: task['service_config'].get(x['name'], x['default'])
                          for x in service_manifest.get('submission_params', [])}
                task['service_config'] = params
                service_task = ServiceTask(task)
                self.log.info(f"[{service_task.sid}] New task received")
            except ValueError as e:
                self.log.error(f"Invalid task received: {str(e)}")
                continue

            # Download file if needed
            if file_required:
                self.status = STATUSES.DOWNLOADING_FILE
                file_path = os.path.join(self.tasking_dir, service_task.fileinfo.sha256)
                received_file_sha256 = None
                self.log.info(f"[{service_task.sid}] Downloading file: {service_task.fileinfo.sha256}")
                try:
                    self.filestore.download(service_task.fileinfo.sha256, file_path)
                    received_file_sha256 = get_sha256_for_file(file_path)
                except FileStoreException:
                    self.status = STATUSES.FILE_NOT_FOUND
                    self.log.error(
                        f"[{service_task.sid}] Requested file not found in the system: {service_task.fileinfo.sha256}")

                # If the file retrieved is different from what we requested, report the error
                if received_file_sha256 and received_file_sha256 != service_task.fileinfo.sha256:
                    self.status = STATUSES.ERROR_FOUND
                    self.log.error(f"[{service_task.sid}] Downloaded ({received_file_sha256}) doesn't match "
                                   f"requested ({service_task.fileinfo.sha256})")

            # Process if we're not already in error
            if self.status not in [STATUSES.ERROR_FOUND, STATUSES.FILE_NOT_FOUND]:
                self.status = STATUSES.PROCESSING
                self.service.handle_task(service_task)

                # Check for the response from the service
                result_json = os.path.join(
                    self.tasking_dir, f"{service_task.sid}_{service_task.fileinfo.sha256}_result.json")
                error_json = os.path.join(
                    self.tasking_dir, f"{service_task.sid}_{service_task.fileinfo.sha256}_error.json")
                if os.path.exists(result_json):
                    self.status = STATUSES.RESULT_FOUND
                elif os.path.exists(error_json):
                    self.status = STATUSES.ERROR_FOUND
                else:
                    self.status = STATUSES.ERROR_FOUND
                    error_json = None

            # Handle the service response
            if self.status == STATUSES.RESULT_FOUND:
                self.log.info(f"[{service_task.sid}] Task successfully completed")
                try:
                    self._handle_task_result(result_json, service_task)
                except RuntimeError as re:
                    if is_recoverable_runtime_error(re):
                        self.log.info(f"[{service_task.sid}] Service trying to use a threadpool during shutdown, "
                                      "sending recoverable error.")
                        self._handle_task_error(service_task)
                    else:
                        raise
            elif self.status == STATUSES.ERROR_FOUND:
                self.log.info(f"[{service_task.sid}] Task completed with errors")
                self._handle_task_error(service_task, error_json_path=error_json)
            elif self.status == STATUSES.FILE_NOT_FOUND:
                self.log.info(f"[{service_task.sid}] Task completed with errors due to missing file from filestore")
                self._handle_task_error(service_task, status="FAIL_NONRECOVERABLE", error_type="EXCEPTION")

    def _handle_task_result(self, result_json_path: str, task: ServiceTask):
        with open(result_json_path, 'r') as f:
            result = json.load(f)

        # Map of file info by SHA256
        result_files = {}
        for file in result['response']['extracted'] + result['response']['supplementary']:
            result_files[file['sha256']] = copy.deepcopy(file)
            file.pop('path', None)

        new_tool_version = result.get('response', {}).get('service_tool_version', None)
        if new_tool_version is not None and self.service_tool_version != new_tool_version:
            self.service_tool_version = new_tool_version

        resp = {'success': False, 'missing_files': []}
        freshen = True

        while not resp['success']:
            for f_sha256 in resp['missing_files']:
                file_info = result_files[f_sha256]
                self.log.info(f"[{task.sid}] Uploading file {file_info['path']} [{file_info['sha256']}]")

                self.tasking_client.upload_file(
                    file_info['path'],
                    file_info['classification'],
                    task.ttl, file_info.get('is_section_image', False))

            try:
                resp = self.tasking_client.task_finished(
                    dict(task=task.as_primitives(), result=result, freshen=freshen), self.client_id,
                    self.service_name, self.metric_factory)
                if resp is None:
                    self._handle_task_error(task, message="No result or error provided by service.",
                                            error_type='EXCEPTION', status='FAIL_NONRECOVERABLE')
                    return
            except ValueError as e:
                self._handle_task_error(task, message=str(e), error_type='EXCEPTION', status='FAIL_NONRECOVERABLE')
                return

            freshen = False

    def _handle_task_error(self, task: ServiceTask, error_json_path=None,
                           message=None, error_type=None, status=None):
        if task is None:
            return

        if self.service:
            version = self.service_config['version']
        else:
            version = '0'

        error = dict(
            response=dict(
                message=message or "The service instance processing this task has terminated unexpectedly.",
                service_name=task.service_name,
                service_version=version,
                status=status or 'FAIL_RECOVERABLE',
            ),
            sha256=task.fileinfo.sha256,
            type=error_type or 'UNKNOWN',
        )

        if error_json_path:
            try:
                with open(error_json_path, 'r') as f:
                    error = json.load(f)
            except (IOError, JSONDecodeError, OSError):
                self.log.exception(f"[{task.sid}] An error occurred while loading service error file.")

        try:
            resp = self.tasking_client.task_finished(
                dict(task=task.as_primitives(), error=error), self.client_id,
                self.service_name, self.metric_factory)
            if resp is None:
                self.log.error(f"[{task.sid}] The tasking client failed to detect the error data.")
        except ValueError as e:
            self.log.exception(
                f"[{task.sid}] An error occured while trying to save the result error in the system: '{str(e)}'")

    def stop(self):
        if self.status == STATUSES.WAITING_FOR_TASK:
            # A task request was sent and a task might be received, so shutdown after giving service time to process it
            self._shutdown_timeout = TASK_REQUEST_TIMEOUT + self.service_config.get('timeout', SHUTDOWN_SECONDS_LIMIT)
        elif self.status not in [STATUSES.INITIALIZING, STATUSES.STOPPING]:
            # A task is currently running, so wait until service timeout before doing a hard stop
            self._shutdown_timeout = self.service_config.get('timeout', SHUTDOWN_SECONDS_LIMIT)
        else:
            # Already the default
            self._shutdown_timeout = SHUTDOWN_SECONDS_LIMIT

        if self.service:
            self.service.stop_service()

        super().stop()


if __name__ == '__main__':
    RunPrivilegedService().serve_forever()
