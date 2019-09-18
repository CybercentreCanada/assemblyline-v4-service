import argparse
import json
import logging
import os
import pprint
import shutil
import tempfile

import yaml

from assemblyline.common import identify
from assemblyline.common.importing import load_module_by_path
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service


class RunService:
    def __init__(self):
        self.service = None
        self.service_class = None
        self.submission_params = None
        self.file_dir = None

    def try_run(self):
        try:
            self.service_class = load_module_by_path(SERVICE_PATH)
        except:
            LOG.error("Could not find service in path. Check your environment variables.")
            raise

        self.load_service_manifest()

        if not os.path.isfile(FILE_PATH):
            LOG.info(f"File not found: {FILE_PATH}")
            return

        self.file_dir = os.path.dirname(FILE_PATH)

        # Create a task.json based on input file
        file_info = identify.fileinfo(FILE_PATH)

        service_task = ServiceTask(dict(
            sid=get_random_id(),
            service_name=SERVICE_NAME,
            service_config=self.submission_params,
            fileinfo=dict(
                magic=file_info['magic'],
                md5=file_info['md5'],
                mime=file_info['mime'],
                sha1=file_info['sha1'],
                sha256=file_info['sha256'],
                size=file_info['size'],
                type=file_info['type'],
            ),
            max_files=100,  # TODO: get the actual value
            ttl=3600,
        ))

        self.service.start_service()

        LOG.info(f"Starting task with SID: {service_task.sid}")

        # Set the working directory to a directory with same parent as input file
        working_dir = os.path.join(self.file_dir,
                                   os.path.splitext(os.path.basename(FILE_PATH))[0] + '_' + SERVICE_NAME.lower())
        if os.path.isdir(working_dir):
            shutil.rmtree(working_dir)
        if not os.path.isdir(working_dir):
            os.makedirs(working_dir)

        # Move the file to be processed to the original directory created by the service base
        dest = os.path.join(tempfile.gettempdir(), SERVICE_NAME.lower(), 'received')
        if os.path.exists(dest):
            shutil.rmtree(dest)
        if not os.path.exists(dest):
            os.makedirs(dest)
        shutil.copyfile(FILE_PATH, os.path.join(dest, service_task.fileinfo.sha256))

        self.service.handle_task(service_task)

        # Move the result.json and extracted/supplementary files to the working directory
        source = os.path.join(tempfile.gettempdir(), SERVICE_NAME.lower(), 'completed')
        files = os.listdir(source)
        for f in files:
            shutil.move(os.path.join(source, f), working_dir)

        # Cleanup files from the original directory created by the service base
        shutil.rmtree(source)
        shutil.rmtree(dest)

        # Validate the generated result
        result_json = os.path.join(working_dir, 'result.json')
        with open(result_json, 'r') as fh:
            try:
                result = Result(json.load(fh))

                # Print the result on console if in debug mode
                if args.debug:
                    f"{SERVICE_NAME.upper()}-RESULT".center(60, '-')
                    for line in pprint.pformat(result.result.as_primitives()).split('\n'):
                        LOG.debug(line)
            except Exception as e:
                LOG.error(f"Invalid result created: {str(e)}")

        LOG.info(f"Successfully completed task. Output directory: {working_dir}")

    def stop(self):
        self.service.stop_service()

    def load_service_manifest(self) -> None:
        service_manifest_yml = os.path.join(os.getcwd(), 'service_manifest.yml')

        if os.path.exists(service_manifest_yml):
            with open(service_manifest_yml) as yml_fh:
                service_manifest_data = yaml.safe_load(yml_fh.read())

            # Pop the 'extra' data from the service manifest
            for x in ['file_required', 'tool_version', 'heuristics']:
                service_manifest_data.pop(x, None)

            # Validate the service manifest
            try:
                self.service = Service(service_manifest_data)
            except Exception as e:
                LOG.error(f"Invalid service manifest: {str(e)}")

            service_config = {}
            if service_manifest_data:
                service_config = service_manifest_data.get('config', {})

            self.submission_params = {x['name']: x['default'] for x in service_manifest_data.get('submission_params', [])}

            self.service = self.service_class(config=service_config)
        else:
            raise Exception("Service manifest YAML file not found in root folder of service.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="turn on debugging mode")
    parser.add_argument("service_path", help="python path of the service")
    parser.add_argument("file_path", help="file path of the file to be processed")

    args = parser.parse_args()

    SERVICE_PATH = args.service_path
    SERVICE_NAME = SERVICE_PATH.split(".")[-1].lower()
    FILE_PATH = args.file_path

    # create logger
    LOG = logging.getLogger(f"assemblyline.service.{SERVICE_NAME}")
    if args.debug:
        LOG.setLevel(logging.DEBUG)
    else:
        LOG.setLevel(logging.INFO)

    rs = RunService()
    rs.try_run()
