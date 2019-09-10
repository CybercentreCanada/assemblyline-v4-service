import argparse
import json
import logging
import os
import tempfile
import time

import yaml

from assemblyline.common.importing import load_module_by_path
from assemblyline.odm.messages.task import Task as ServiceTask


class RunService:
    def __init__(self):
        self.service = None
        self.service_class = None
        self.received_dir = None

    def try_run(self):
        try:
            self.service_class = load_module_by_path(SERVICE_PATH)
        except:
            LOG.error("Could not find service in path. Check your environment variables.")
            raise

        self.load_service_manifest()

        self.received_dir = os.path.join(tempfile.gettempdir(), SERVICE_NAME.lower(), 'received')
        self.received_dir = args.input_dir
        if not os.path.isdir(self.received_dir):
            os.makedirs(self.received_dir)

        self.service.start_service()

        task_json_path = os.path.join(self.received_dir, 'task.json')
        if not os.path.exists(task_json_path):
            LOG.info(f"No 'task.json' found in input directory. "
                     f"Add 'task.json' to '{self.received_dir}' before running this script!")
            return

        LOG.info(f"Task found in: {task_json_path}")
        with open(task_json_path, 'r') as f:
            task = ServiceTask(json.load(f))
        self.service.handle_task(task)

        while os.path.exists(task_json_path):
            time.sleep(1)

    def stop(self):
        self.service.stop_service()

    def load_service_manifest(self) -> None:
        service_manifest_yml = os.path.join(os.getcwd(), 'service_manifest.yml')

        if os.path.exists(service_manifest_yml):
            with open(service_manifest_yml) as yml_fh:
                service_manifest_data = yaml.safe_load(yml_fh.read())

            service_config = {}
            if service_manifest_data:
                service_config = service_manifest_data.get('config', {})

            self.service = self.service_class(config=service_config)
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
    LOG = logging.getLogger(f"assemblyline.service.{SERVICE_NAME}")
    if args.debug:
        LOG.setLevel(logging.DEBUG)
    else:
        LOG.setLevel(logging.INFO)

    rs = RunService()
    rs.try_run()
