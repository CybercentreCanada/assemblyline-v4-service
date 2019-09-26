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

        self.wait_start = None

        self.service = None
        self.service_class = None
        self.service_config = None
        self.service_tool_version = None
        self.service_file_required = None
        self.received_folder_path = None
        self.completed_folder_path = None
        self.task_fifo = None
        self.done_fifo = None

    def try_run(self):
        try:
            self.service_class = load_module_by_path(SERVICE_PATH)
        except:
            self.log.error("Could not find service in path.")
            raise

        self.load_service_attributes()

        self.received_folder_path = os.path.join(tempfile.gettempdir(), SERVICE_NAME.lower(), 'received')
        if not os.path.isdir(self.received_folder_path):
            os.makedirs(self.received_folder_path)

        self.completed_folder_path = os.path.join(tempfile.gettempdir(), SERVICE_NAME.lower(), 'completed')

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

            self.log.info(f"Task found in: {task_json_path}")
            with open(task_json_path, 'r') as f:
                task = ServiceTask(json.load(f))
            self.service.handle_task(task)

            # Notify task handler that processing is done
            if "result.json" in os.listdir(self.completed_folder_path):
                msg = f"{json.dumps([os.path.join(self.completed_folder_path, 'result.json'), SUCCESS])}\n"
            elif "error.json" in os.listdir(self.completed_folder_path):
                msg = f"{json.dumps([os.path.join(self.completed_folder_path, 'error.json'), ERROR])}\n"
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

    def load_service_attributes(self) -> None:
        service_manifest_data = helper.get_service_manifest()

        self.service_config = service_manifest_data.get('config', {})

        self.service = self.service_class(config=self.service_config)

        self.service_tool_version = self.service.get_tool_version()

        self.service_file_required = service_manifest_data.get('file_required', True)

        # Update the service version with the whole version
        service_manifest_data['version'] = self.service.get_service_version()

        # Save a copy of the service manifest for the service client to use
        with open(self.service_manifest_yml, 'w') as yml_fh:
            yaml.safe_dump(service_manifest_data, yml_fh)


if __name__ == '__main__':
    RunService().serve_forever()
