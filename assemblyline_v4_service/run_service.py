import json
import os
import select
import tempfile

import yaml

from assemblyline.common.importing import load_module_by_path
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_core.server_base import ServerBase
from assemblyline_v4_service.common import helper

SERVICE_PATH = os.environ['SERVICE_PATH']
SERVICE_NAME = SERVICE_PATH.split(".")[-1].lower()
SHUTDOWN_SECONDS_LIMIT = 10
TASK_FIFO_PATH = "/tmp/task.fifo"
DONE_FIFO_PATH = "/tmp/done.fifo"

SUCCESS = "RESULT_FOUND"
ERROR = "ERROR_FOUND"


class RunService(ServerBase):
    def __init__(self, shutdown_timeout: int = SHUTDOWN_SECONDS_LIMIT):
        super(RunService, self).__init__(f'assemblyline.service.{SERVICE_NAME}', shutdown_timeout=shutdown_timeout)

        self.classification_yml = '/etc/assemblyline/classification.yml'
        self.service_manifest_yml = os.path.join(tempfile.gettempdir(), 'service_manifest.yml')

        self.status = None

        self.service = None
        self.service_class = None
        self.service_config = None
        self.service_tool_version = None
        self.service_file_required = None
        self.task_fifo = None
        self.done_fifo = None

    def try_run(self):
        try:
            self.service_class = load_module_by_path(SERVICE_PATH)
        except Exception:
            self.log.error("Could not find service in path.")
            raise

        self.load_service_attributes()

        # Start task receiving fifo
        self.log.info('Waiting for receive task named pipe to be ready...')
        if not os.path.exists(TASK_FIFO_PATH):
            os.mkfifo(TASK_FIFO_PATH)
        self.task_fifo = open(TASK_FIFO_PATH, "r")

        # Start task completing fifo
        self.log.info('Waiting for complete task named pipe to be ready...')
        if not os.path.exists(DONE_FIFO_PATH):
            os.mkfifo(DONE_FIFO_PATH)
        self.done_fifo = open(DONE_FIFO_PATH, "w")

        # Reload the service again with the new config parameters (if any) received from service server
        self.load_service_attributes(save=False)
        self.service.start_service()

        while self.running:
            try:
                read_ready, _, _ = select.select([self.task_fifo], [], [], 1)
                if not read_ready:
                    continue
            except ValueError:
                self.log.info('Task fifo is closed. Cleaning up...')
                return

            task_json_path = self.task_fifo.readline().strip()
            if not task_json_path:
                self.log.info('Received an empty message for Task fifo. Cleaning up...')
                return

            self.log.info(f"Task found in: {task_json_path}")
            with open(task_json_path, 'r') as f:
                task = ServiceTask(json.load(f))
            self.service.handle_task(task)

            # Notify task handler that processing is done
            result_json = os.path.join(tempfile.gettempdir(), f"{task.sid}_{task.fileinfo.sha256}_result.json")
            error_json = os.path.join(tempfile.gettempdir(), f"{task.sid}_{task.fileinfo.sha256}_error.json")
            if os.path.exists(result_json):
                msg = f"{json.dumps([result_json, SUCCESS])}\n"
            elif os.path.exists(error_json):
                msg = f"{json.dumps([error_json, ERROR])}\n"
            else:
                msg = f"{json.dumps([None, ERROR])}\n"

            self.done_fifo.write(msg)
            self.done_fifo.flush()

    def stop(self):
        self.log.info("Closing named pipes...")
        if self.done_fifo is not None:
            self.done_fifo.close()
        if self.task_fifo is not None:
            self.task_fifo.close()

        self.service.stop_service()

        super().stop()

    def load_service_attributes(self, save=True) -> None:
        service_manifest_data = helper.get_service_manifest()

        self.service_config = service_manifest_data.get('config', {})

        self.service = self.service_class(config=self.service_config)

        self.service_tool_version = self.service.get_tool_version()

        self.service_file_required = service_manifest_data.get('file_required', True)

        # Update the service version with the whole version
        service_version = service_manifest_data['version']
        if isinstance(service_version, int) or '.' not in service_version:
            service_manifest_data['version'] = self.service.get_service_version()

        # Save a copy of the service manifest for the service client to use
        if save:
            with open(self.service_manifest_yml, 'w') as yml_fh:
                yaml.safe_dump(service_manifest_data, yml_fh)


if __name__ == '__main__':
    RunService().serve_forever()
