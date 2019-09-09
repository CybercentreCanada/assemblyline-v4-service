import json
import os
import tempfile
import time
from queue import Empty

import yaml
from watchdog.events import PatternMatchingEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import EventQueue

from assemblyline.common.importing import load_module_by_path
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_core.server_base import ServerBase
from assemblyline_v4_service.common import helper

SERVICE_PATH = os.environ['SERVICE_PATH']
SERVICE_NAME = SERVICE_PATH.split(".")[-1].lower()
SHUTDOWN_SECONDS_LIMIT = 10


class FileEventHandler(PatternMatchingEventHandler):
    def __init__(self, queue, patterns):
        PatternMatchingEventHandler.__init__(self, patterns=patterns)
        self.queue = queue

    def process(self, event):
        if event.src_path.endswith('task.json'):
            self.queue.put(event.src_path)

    def on_created(self, event):
        self.process(event)


class FileWatcher:
    def __init__(self, queue, watch_path):
        self._observer = None
        self._queue = queue
        self._watch_path = watch_path

    def start(self):
        event_handler = FileEventHandler(self._queue, patterns=['*.json'])
        self._observer = Observer()
        self._observer.schedule(event_handler, path=self._watch_path)
        self._observer.daemon = True
        self._observer.start()

    def stop(self):
        self._observer.stop()
        pass


class RunService(ServerBase):
    def __init__(self, shutdown_timeout: int = SHUTDOWN_SECONDS_LIMIT):
        super(RunService, self).__init__(f'assemblyline.service.{SERVICE_NAME}', shutdown_timeout=shutdown_timeout)

        self.classification_yml = '/etc/assemblyline/classification.yml'
        self.service_manifest_yml = os.path.join(tempfile.gettempdir(), 'service_manifest.yml')

        self.status = None

        self.wait_start = None
        self.queue = EventQueue()
        self.file_watcher = None

        self.service = None
        self.service_class = None
        self.service_config = None
        self.service_tool_version = None
        self.service_file_required = None
        self.received_folder_path = None

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

        # Start the file watcher
        self.file_watcher = FileWatcher(self.queue, self.received_folder_path)
        self.file_watcher.start()
        self.log.info(f"Started watching folder for tasks: {self.received_folder_path}")

        self.service.start_service()

        while self.running:
            try:
                task_json_path = self.queue.get(timeout=1)
            except Empty:
                continue

            self.log.info(f"Task found in: {task_json_path}")
            with open(task_json_path, 'r') as f:
                task = ServiceTask(json.load(f))
            self.service.handle_task(task)

            while os.path.exists(task_json_path):
                time.sleep(1)

            self.queue.task_done()

    def stop(self):
        self.file_watcher.stop()
        self.log.info(f"Stopped watching folder for tasks: {self.received_folder_path}")

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
