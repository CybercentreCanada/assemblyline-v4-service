import json
import os
import select
import tempfile

from assemblyline.common.importing import load_module_by_path
from assemblyline.common.version import FRAMEWORK_VERSION, SYSTEM_VERSION
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_core.server_base import ServerBase
from assemblyline_v4_service.common import helper

SERVICE_PATH = os.environ['SERVICE_PATH']
SERVICE_NAME = SERVICE_PATH.split(".")[-1].lower()
SHUTDOWN_SECONDS_LIMIT = 10

SUCCESS = "RESULT_FOUND"
ERROR = "ERROR_FOUND"


class RunService(ServerBase):
    def __init__(self, shutdown_timeout: int = SHUTDOWN_SECONDS_LIMIT):
        super(RunService, self).__init__(f'assemblyline.service.{SERVICE_NAME}', shutdown_timeout=shutdown_timeout)

        self.classification_yml = '/etc/assemblyline/classification.yml'
        self.service_manifest = os.path.join(os.getcwd(), 'service_manifest.yml')
        self.runtime_service_manifest = f"/tmp/{os.environ.get('RUNTIME_PREFIX', 'service')}_manifest.yml"
        self.task_fifo_path = f"/tmp/{os.environ.get('RUNTIME_PREFIX', 'service')}_task.fifo"
        self.done_fifo_path = f"/tmp/{os.environ.get('RUNTIME_PREFIX', 'service')}_done.fifo"

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

        if not os.path.exists(self.runtime_service_manifest):
            # In case service tag have not been overwritten we will do it here (This is mainly use during debugging)
            service_tag = os.environ.get("SERVICE_TAG", f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.0.dev0").encode("utf-8")

            with open(self.service_manifest, "rb") as srv_manifest:
                with open(self.runtime_service_manifest, "wb") as runtime_manifest:
                    for line in srv_manifest.readlines():
                        runtime_manifest.write(line.replace(b"$SERVICE_TAG", service_tag))

        # Start task receiving fifo
        self.log.info('Waiting for receive task named pipe to be ready...')
        if not os.path.exists(self.task_fifo_path):
            os.mkfifo(self.task_fifo_path)
        self.task_fifo = open(self.task_fifo_path, "r")

        # Start task completing fifo
        self.log.info('Waiting for complete task named pipe to be ready...')
        if not os.path.exists(self.done_fifo_path):
            os.mkfifo(self.done_fifo_path)
        self.done_fifo = open(self.done_fifo_path, "w")

        # Reload the service again with the new config parameters (if any) received from service server
        self.load_service_attributes()
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

        if self.service:
            self.service.stop_service()

        super().stop()

    def load_service_attributes(self) -> None:
        service_manifest_data = helper.get_service_manifest()

        self.service_config = service_manifest_data.get('config', {})

        self.service = self.service_class(config=self.service_config)

        self.service_tool_version = self.service.get_tool_version()

        self.service_file_required = service_manifest_data.get('file_required', True)


if __name__ == '__main__':
    RunService().serve_forever()
