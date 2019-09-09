import argparse
import json
import logging
import os
import tempfile
import time
from queue import Empty

import yaml
from watchdog.events import PatternMatchingEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import EventQueue

from assemblyline.common.importing import load_module_by_path
from assemblyline.common.logformat import AL_LOG_FORMAT
from assemblyline.odm.messages.task import Task as ServiceTask


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


class RunService:
    def __init__(self):
        self.classification_yml = '/etc/assemblyline/classification.yml'
        self.service_manifest_yml = os.path.join(tempfile.gettempdir(), 'service_manifest.yml')

        self.status = None

        self.wait_start = None
        self.queue = EventQueue()
        self.file_watcher = None

        self.service = None
        self.service_class = None
        self.service_config = {}
        self.received_dir = None

    def try_run(self):
        try:
            self.service_class = load_module_by_path(SERVICE_PATH)
        except:
            LOG.error("Could not find service in path.")
            raise

        self.load_service_manifest()

        self.received_dir = os.path.join(tempfile.gettempdir(), SERVICE_NAME.lower(), 'received')
        if not os.path.isdir(self.received_dir):
            os.makedirs(self.received_dir)

        # Start the file watcher
        self.file_watcher = FileWatcher(self.queue, self.received_dir)
        self.file_watcher.start()
        LOG.info(f"Started watching folder for tasks: {self.received_dir}")

        self.service.start_service()

        try:
            task_json_path = self.queue.get(timeout=1)
        except Empty:
            LOG.debug(f"No 'task.json' found in directory: {self.received_dir}. "
                      "Add 'task.json' before running this script!")
            return

        LOG.info(f"Task found in: {task_json_path}")
        with open(task_json_path, 'r') as f:
            task = ServiceTask(json.load(f))
        self.service.handle_task(task)

        while os.path.exists(task_json_path):
            time.sleep(1)

        self.queue.task_done()

    def stop(self):
        self.file_watcher.stop()
        LOG.info(f"Stopped watching folder for tasks: {self.received_dir}")

        self.service.stop_service()

    def load_service_manifest(self) -> None:
        service_manifest_yml = os.path.join(os.getcwd(), 'service_manifest.yml')

        if os.path.exists(service_manifest_yml):
            with open(service_manifest_yml) as yml_fh:
                service_manifest_data = yaml.safe_load(yml_fh.read())

            if service_manifest_data:
                self.service_config = service_manifest_data.get('config', {})

            self.service = self.service_class(config=self.service_config)
        else:
            raise Exception("Service manifest YAML file not found in root folder of service.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="turn on debugging mode")
    parser.add_argument("service_path", help="python path of the service")
    parser.add_argument("input_dir", help="path to directory where 'task.json' and the file to be scanned is located")
    parser.add_argument("-o", "--output_dir", help="path to directory where 'result.json' and extracted/supplementary "
                                                   "files should be outputted")

    args = parser.parse_args()

    SERVICE_PATH = args.service_path
    SERVICE_NAME = SERVICE_PATH.split(".")[-1].lower()

    # create logger
    LOG = logging.getLogger(f"service.{SERVICE_NAME}")
    LOG.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    if args.debug:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)

    # create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(AL_LOG_FORMAT)
    # add ch to logger
    LOG.addHandler(ch)

    rs = RunService()
    rs.try_run()

