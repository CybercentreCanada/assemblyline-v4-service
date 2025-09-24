import copy
import json
import os
import re
import select
import shutil
import signal
import tempfile
import time
from json import JSONDecodeError
from typing import Any, Optional

import requests
import yaml
from assemblyline_core.server_base import ServerBase

from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.str_utils import StringTable
from assemblyline.odm import SHA256_REGEX as SHA256_REGEX_PATTERN
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.service import Service

STATUSES = StringTable('STATUSES', [
    ('INITIALIZING', 0),
    ('WAITING_FOR_TASK', 1),
    ('DOWNLOADING_FILE', 2),
    ('DOWNLOADING_FILE_COMPLETED', 3),
    ('PROCESSING', 4),
    ('RESULT_FOUND', 5),
    ('ERROR_FOUND', 6),
    ('STOPPING', 7),
    ('FILE_NOT_FOUND', 8),
])

DEFAULT_API_KEY = 'ThisIsARandomAuthKey...ChangeMe!'
SHUTDOWN_SECONDS_LIMIT = 10
SUPPORTED_API = 'v1'
DEFAULT_REQUEST_TIMEOUT = int(os.environ.get("SERVICE_CLIENT_DEFAULT_REQUEST_TIMEOUT", 180))
TASK_REQUEST_TIMEOUT = int(os.environ.get('TASK_REQUEST_TIMEOUT', 30))
FILE_REQUEST_TIMEOUT = int(os.environ.get('FILE_REQUEST_TIMEOUT', 180))
SHA256_REGEX = re.compile(SHA256_REGEX_PATTERN)

# The number of tasks a service will complete before stopping, letting the environment start a new container.
# By default there is no limit, but this lets the orchestration environment set one
TASK_COMPLETE_LIMIT = float(os.environ.get('AL_SERVICE_TASK_LIMIT', 'inf'))


class ServiceServerException(Exception):
    pass


class TaskHandler(ServerBase):
    def __init__(self, shutdown_timeout: float = SHUTDOWN_SECONDS_LIMIT, api_host: Optional[str] = None,
                 api_key: Optional[str] = None, container_id: Optional[str] = None, register_only: bool = False,
                 container_mode: bool = False) -> None:
        super().__init__('assemblyline.service.task_handler', shutdown_timeout=shutdown_timeout)

        self.service_manifest_yml = f"/tmp/{os.environ.get('RUNTIME_PREFIX', 'service')}_manifest.yml"

        self.status = None
        self.register_only = register_only
        self.container_mode = container_mode
        self.wait_start = None
        self.task_fifo_path = f"/tmp/{os.environ.get('RUNTIME_PREFIX', 'service')}_task.fifo"
        self.done_fifo_path = f"/tmp/{os.environ.get('RUNTIME_PREFIX', 'service')}_done.fifo"
        self.task_fifo = None
        self.done_fifo = None
        self.tasks_processed = 0

        self.service: Optional[Service] = None
        self.service_manifest_data = None
        self.service_heuristics: list[dict] = []
        self.service_tool_version: Optional[str] = None
        self.file_required = None
        self.service_api_host: str = api_host or os.environ.get('SERVICE_API_HOST') or 'http://localhost:5003'
        self.service_api_key: str = api_key or os.environ.get('SERVICE_API_KEY') or DEFAULT_API_KEY
        self.container_id: str = container_id or os.environ.get('HOSTNAME') or 'dev-service'
        self.session = requests.Session()
        self.headers: dict[str, str] = {}
        self.task = None
        self.tasking_dir = os.environ.get('TASKING_DIR', tempfile.gettempdir())

    def _path(self, prefix: str, *args: str) -> str:
        """
        Calculate the API path using the prefix as shown:
            /api/v1/<prefix>/[arg1/[arg2/[...]]][?k1=v1[...]]
        """
        return os.path.join(self.service_api_host, 'api', SUPPORTED_API, prefix, *args) + '/'

    def start(self) -> None:
        self.log.info("Loading service manifest...")
        if self.service_api_key == DEFAULT_API_KEY:
            key = '**default key** - You should consider setting SERVICE_API_KEY in your service containers'
        else:
            key = '**custom key**'
        self.log.info("---- TaskHandler config ----")
        self.log.info(f"SERVICE_API_HOST: {self.service_api_host}")
        self.log.info(f"SERVICE_APIKEY: {key}")
        self.log.info(f"CONTAINER-ID: {self.container_id}")
        self.load_service_manifest()
        self.log.info("----------------------------")

        self.headers = {
            "X-APIKey": self.service_api_key,
            "Container-ID": self.container_id,
            "Service-Name": self.service.name,
            "Service-Version": self.service.version,
            "Service-Tool-Version": self.service_tool_version or '',
        }

        self.session.headers.update(self.headers)
        if self.service_api_host.startswith('https'):
            self.session.verify = os.environ.get('SERVICE_SERVER_ROOT_CA_PATH', '/etc/assemblyline/ssl/al_root-ca.crt')

        super().start()
        signal.signal(signal.SIGUSR1, self.handle_service_crash)

    # noinspection PyUnusedLocal
    def handle_service_crash(self, signum, frame):
        """USER1 is raised when the service has crashed, this represents an unknown error."""
        if self.task is not None:
            self.handle_task_error(self.task)
        self.stop()

    def load_service_manifest(self):
        # Load from the service manifest yaml
        while not self.service:
            if os.path.exists(self.service_manifest_yml):
                with open(self.service_manifest_yml, 'r') as yml_fh:
                    self.service_manifest_data = yaml.safe_load(yml_fh)
                    if not self.service_manifest_data:
                        time.sleep(.1)
                        continue

                    self.service_tool_version = self.service_manifest_data.get('tool_version')
                    self.file_required = self.service_manifest_data.get('file_required', True)

                    # Save the heuristics from service manifest
                    for heuristic in self.service_manifest_data.get('heuristics', []):
                        self.service_heuristics.append(heuristic)

                    # Pop the 'extra' data from the service manifest to build the service object
                    service = copy.deepcopy(self.service_manifest_data)
                    for x in ['file_required', 'tool_version', 'heuristics']:
                        service.pop(x, None)
                    self.service = Service(service)

            if not self.service:
                time.sleep(.1)
            else:
                self.log.info(f"SERVICE: {self.service.name}")
                self.log.info(f"HEURISTICS_COUNT: {len(self.service_heuristics)}")

    def update_service_manifest(self, data):
        for x in ['version']:
            data.pop(x, None)

        if os.path.exists(self.service_manifest_yml):
            with open(self.service_manifest_yml, 'r') as yml_fh:
                self.service_manifest_data = yaml.safe_load(yml_fh)

                self.service_manifest_data.update(data)

            with open(self.service_manifest_yml, 'w') as yml_fh:
                yaml.safe_dump(self.service_manifest_data, yml_fh)

    # noinspection PyBroadException
    def cleanup_working_directory(self, folder_path):
        for file in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file)
            if file_path not in [self.task_fifo_path, self.done_fifo_path, self.service_manifest_yml]:
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception:
                    pass

    def request_with_retries(self, method: str, url: str,
                             get_api_response=True, max_retry=None, **kwargs) -> Optional[Any]:
        if 'headers' in kwargs:
            self.session.headers.update(kwargs['headers'])
            kwargs.pop('headers')
        header_dump = '; '.join(f"{k}={v}" for k, v in self.session.headers.items())
        self.log.debug('query headers: ' + header_dump)
        kwargs.setdefault('timeout', DEFAULT_REQUEST_TIMEOUT)

        retry = 0

        while max_retry is None or retry < max_retry:
            if retry:
                time.sleep(min(2, 2 ** (retry - 7)))
                stream = kwargs.get('files', {}).get('file', None)
                if stream and 'seek' in dir(stream):
                    stream.seek(0)

            try:
                func = getattr(self.session, method)
                resp = func(url, **kwargs)

                if get_api_response:
                    if resp.status_code == 400 and resp.json():
                        self.log.exception(resp.json()['api_error_message'])
                        raise ServiceServerException(resp.json()['api_error_message'])
                    else:
                        resp.raise_for_status()

                    return resp.json()['api_response']
                else:
                    return resp
            except requests.ConnectionError:
                if not retry:
                    self.log.info("Service server is unreachable...")
                elif retry % 10 == 0:
                    self.log.warning(f"Service server has been unreachable for the past {retry} attempts. "
                                     "Is there something wrong with it?")
            except requests.Timeout as e:  # Handles ConnectTimeout and ReadTimeout
                self.log.warning(f"We've timed out on: {url} ({e}) Retrying..")
                pass
            except requests.HTTPError as e:
                self.log.error(str(e))
                raise
            except requests.exceptions.RequestException as e:  # All other types of exceptions
                self.log.error(str(e))
                raise

            retry += 1

        return None

    def try_run(self):
        self.initialize_service()
        if not os.path.exists(self.tasking_dir):
            os.makedirs(self.tasking_dir)

        while self.running:
            if self.tasks_processed >= TASK_COMPLETE_LIMIT:
                self.stop()
                return

            self.task = self.get_task()
            if not self.task:
                continue

            # Download file if required by service; if file_path was returned, the file was downloaded successfully
            json_path = None
            start_task_process = bool(self.download_file(self.task.fileinfo.sha256, self.task.sid)) \
                if self.file_required else True

            if start_task_process:
                # Save task as JSON, so that run_service can start processing task
                task_json_path = os.path.join(self.tasking_dir,
                                              f'{self.task.sid}_{self.task.fileinfo.sha256}_task.json')
                with open(task_json_path, 'w') as f:
                    json.dump(self.task.as_primitives(), f)
                self.log.info(f"[{self.task.sid}] Saved task to: {task_json_path}")

                self.status = STATUSES.PROCESSING

                try:
                    # Send tasking message to run_service
                    self.task_fifo.write(f"{task_json_path}\n")
                    self.task_fifo.flush()

                    while True:
                        read_ready, _, _ = select.select([self.done_fifo], [], [], 1)
                        if read_ready:
                            break

                    done_msg = self.done_fifo.readline().strip()
                    try:
                        json_path, self.status = json.loads(done_msg)
                    except JSONDecodeError:
                        # Bad message received reset pipes
                        self.task_fifo = None
                        self.done_fifo = None
                        if self.running:
                            self.log.error(f"[{self.task.sid}] Done pipe received an invalid message: {done_msg}")
                        self.status = STATUSES.ERROR_FOUND
                except (BrokenPipeError, ValueError):
                    # Pipes are broken, reset them
                    self.task_fifo = None
                    self.done_fifo = None
                    if self.running:
                        self.log.error(f"[{self.task.sid}] One of the pipes to the service is broken. "
                                       f"Marking task as failed recoverable...")
                    self.status = STATUSES.ERROR_FOUND

            # Send task result
            self.tasks_processed += 1
            if self.status == STATUSES.RESULT_FOUND:
                self.log.info(f"[{self.task.sid}] Task successfully completed")
                self.handle_task_result(json_path, self.task)
            elif self.status == STATUSES.ERROR_FOUND:
                self.log.info(f"[{self.task.sid}] Task completed with errors")
                self.handle_task_error(self.task, error_json_path=json_path)
            elif self.status == STATUSES.FILE_NOT_FOUND:
                self.log.info(f"[{self.task.sid}] Task completed with errors due to missing file from filestore")
                self.handle_task_error(self.task, status="FAIL_NONRECOVERABLE", error_type="EXCEPTION")

            # Cleanup contents of tempdir which contains task json, result json, and working directory of service
            self.cleanup_working_directory(self.tasking_dir)
            self.task = None

            # Reconnect or quit depending on mode
            if self.done_fifo is None or self.task_fifo is None:
                if self.container_mode:
                    self.stop()
                    return

                self.connect_pipes()

    def connect_pipes(self):
        # Start task receiving fifo
        self.log.info('Waiting for receive task named pipe to be ready...')
        while not os.path.exists(self.task_fifo_path):
            if not self.running:
                return
            time.sleep(1)
        self.task_fifo = open(self.task_fifo_path, "w")

        # Start task completing fifo
        self.log.info('Waiting for complete task named pipe to be ready...')
        while not os.path.exists(self.done_fifo_path):
            if not self.running:
                return
            time.sleep(1)
        self.done_fifo = open(self.done_fifo_path, "r")

    def initialize_service(self):
        self.status = STATUSES.INITIALIZING
        r = self.request_with_retries('put', self._path('service', 'register'), json=self.service_manifest_data)
        if not r['keep_alive'] or self.register_only:
            self.log.info(f"Service registered with {len(r['new_heuristics'])} heuristics. Now stopping...")
            self.status = STATUSES.STOPPING
            self.stop()
            return
        self.log.info("Service registered with %d heuristics.", len(r['new_heuristics']))

        # Update service manifest with data received from service server
        self.update_service_manifest(r['service_config'])

        # Connect to the different name pipes
        self.connect_pipes()

    def get_task(self) -> ServiceTask:
        self.status = STATUSES.WAITING_FOR_TASK
        task = None
        headers = {"Timeout": str(TASK_REQUEST_TIMEOUT)}
        self.log.info(f"Requesting a task with {TASK_REQUEST_TIMEOUT}s timeout...")
        r = self.request_with_retries('get', self._path('task'), headers=headers, timeout=TASK_REQUEST_TIMEOUT*2)
        if r['task'] is False:  # No task received
            self.log.info("No task received")
        else:  # Task received
            try:
                # Inspect task to ensure submission parameters are given, add defaults where necessary
                params = {x.name: x.default for x in self.service.submission_params}
                params.update(r['task']['service_config'])
                r['task']['service_config'] = params
                task = ServiceTask(r['task'])
                self.log.info(f"[{task.sid}] New task received")
            except ValueError as e:
                self.log.error(f"Invalid task received: {str(e)}")
                # TODO: return error to service server

        return task

    def download_file(self, sha256, sid) -> Optional[str]:
        if not SHA256_REGEX.match(sha256):
            # If the SHA256 is not valid, we cannot download the file
            self.log.error(f"[{sid}] Invalid SHA256 provided: {sha256}")
            self.status = STATUSES.ERROR_FOUND
            return None

        self.status = STATUSES.DOWNLOADING_FILE
        received_file_sha256 = ''
        file_path = None
        self.log.info(f"[{sid}] Downloading file: {sha256}")
        response = self.request_with_retries('get', self._path('file', sha256),
                                             get_api_response=False, max_retry=3, headers=self.headers,
                                             timeout=FILE_REQUEST_TIMEOUT)
        if response is not None:
            # Check if we got a 'good' response
            if response.status_code == 200:
                file_path = os.path.join(self.tasking_dir, sha256)
                with open(file_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024):
                        if chunk:  # filter out keep-alive new chunks
                            f.write(chunk)

                received_file_sha256 = get_sha256_for_file(file_path)

                # If the file retrieved is different from what we requested, report the error
                if received_file_sha256 != sha256:
                    self.log.error(f"[{sid}] Downloaded ({received_file_sha256}) doesn't match requested ({sha256}). "
                                   "Reporting task error to service server.")
                    self.status = STATUSES.ERROR_FOUND
                    return

                # Otherwise, this should be what we asked for, therefore success!
                self.status = STATUSES.DOWNLOADING_FILE_COMPLETED
                return file_path
            elif response.status_code == 404:
                self.log.error(f"[{sid}] Requested file not found in the system: {sha256}")
                self.status = STATUSES.FILE_NOT_FOUND
                return
            else:
                self.log.warning(f'[{sid}] Unknown response during file retrieval: '
                                 f'{response.reason}({response.status_code})')
                self.status = STATUSES.ERROR_FOUND
                return

        self.log.error(f"[{sid}] No response given for file {sha256}. Reporting task error to service server.")
        self.status = STATUSES.ERROR_FOUND
        return

    def handle_task_result(self, result_json_path: str, task: ServiceTask):
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
            self.session.headers.update({'Service-Tool-Version': self.service_tool_version})
            self.headers.update({'Service-Tool-Version': self.service_tool_version})

        data = dict(task=task.as_primitives(), result=result, freshen=True)
        try:
            r = self.request_with_retries('post', self._path('task'), json=data, timeout=TASK_REQUEST_TIMEOUT)

            if not r['success'] and r['missing_files']:
                while not r['success'] and r['missing_files']:
                    for f_sha256 in r['missing_files']:
                        file_info = result_files[f_sha256]
                        headers = {
                            "Sha256": file_info['sha256'],
                            "Classification": file_info['classification'],
                            "Ttl": str(task.ttl),
                            "Is-Section-Image": str(file_info.get('is_section_image', False)),
                            "Is-Supplementary": str(file_info.get('is_supplementary', False))
                        }

                        with open(file_info['path'], 'rb') as fh:
                            # Upload the file requested by service server
                            self.log.info(f"[{task.sid}] Uploading file {file_info['path']} [{file_info['sha256']}]")
                            try:
                                self.request_with_retries('put', self._path('file'), files=dict(file=fh),
                                                          headers=headers, timeout=FILE_REQUEST_TIMEOUT)
                            except ServiceServerException as e:
                                if "does not match expected file hash" in str(e):
                                    self.log.warning(f"File upload of '{file_info['path']}' failed.")
                                raise

                    data['freshen'] = False
                    r = self.request_with_retries('post', self._path('task'), json=data, timeout=TASK_REQUEST_TIMEOUT)
        except (ServiceServerException, requests.HTTPError) as e:
            self.handle_task_error(task, message=str(e), error_type='EXCEPTION', status='FAIL_NONRECOVERABLE')

    def handle_task_error(self, task: ServiceTask, error_json_path: Optional[str] = None,
                          message=None, error_type=None, status=None):
        if task is None:
            return

        if self.service:
            version = self.service.version
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

        data = dict(task=task.as_primitives(), error=error)
        self.request_with_retries('post', self._path('task'), json=data, timeout=TASK_REQUEST_TIMEOUT)

    def stop(self):
        if self.status == STATUSES.WAITING_FOR_TASK:
            # A task request was sent and a task might be received, so shutdown after giving service time to process it
            self._shutdown_timeout = TASK_REQUEST_TIMEOUT + self.service.timeout
        elif self.status != STATUSES.INITIALIZING:
            # A task is currently running, so wait until service timeout before doing a hard stop
            self._shutdown_timeout = self.service.timeout
        else:
            # Already the default
            self._shutdown_timeout = SHUTDOWN_SECONDS_LIMIT

        super().stop()

        # We only want to close the tasking pipe to trigger the service to stop waiting.
        # We need to wait on the service to finish the current task and close our done_fifo
        # pipe so that it can be sent back to the system.
        self.log.info("Closing task_fifo named pipes...")
        if self.task_fifo is not None:
            try:
                self.task_fifo.close()
            except BrokenPipeError:
                pass


if __name__ == '__main__':
    import sys
    register_arg = os.environ.get('REGISTER_ONLY', 'False').lower() == 'true'
    register_arg |= '--register' in sys.argv

    ctr_mode = os.environ.get("CONTAINER_MODE", "False").lower() == 'true'
    TaskHandler(register_only=register_arg, container_mode=ctr_mode).serve_forever()
