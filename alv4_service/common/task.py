import hashlib
import json
import logging
import os
import shutil
import tempfile
import time

from alv4_service.common import helper
from assemblyline.common import log
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.result import Result, File

Classification = helper.get_classification()

class Task:
    def __init__(self, task: ServiceTask):
        log.init_logging(log_level=logging.INFO)
        self.log = logging.getLogger(f'{task.service_name.lower()}')

        self._result = Result
        self._working_directory = None
        self.drop_file = False
        self.error_message = None
        self.error_status = None
        self.error_type = "EXCEPTION"
        self.extracted = []
        self.oversized = False
        self.service_name = task.service_name
        self.service_tool_version = None
        self.service_version = None
        self.sha256 = task.fileinfo.sha256
        self.sid = task.sid
        self.supplementary = []
        self.task_hash = hashlib.md5((str(task.sid + task.fileinfo.sha256).encode('utf-8'))).hexdigest()
        self.type = task.fileinfo.type


    def add_extracted(self, path, name, description, classification: Classification = Classification.UNRESTRICTED):
        # Move extracted file to base of working directory
        file_path = os.path.join(self._working_directory, name)
        folder_path = os.path.dirname(path)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        if not os.path.exists(file_path):
            shutil.move(name, file_path)

        sha256 = get_sha256_for_file(path)

        # Initialize a default file
        file = File()

        file.name = name
        file.sha256 = sha256
        file.description = description
        file.classification = classification

        self.extracted.append(file)

    def add_supplementary(self, path, name, description, classification: Classification = Classification.UNRESTRICTED):
        # Move supplementary file to base of working directory
        file_path = os.path.join(self._working_directory, name)
        folder_path = os.path.dirname(path)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        if not os.path.exists(file_path):
            shutil.move(name, file_path)

        sha256 = get_sha256_for_file(path)

        # Initialize a default file
        file = File()

        file.name = name
        file.sha256 = sha256
        file.description = description
        file.classification = classification

        self.supplementary.append(file)

    def clear_extracted(self):
        self.extracted.clear()

    def clear_supplementary(self):
        self.supplementary.clear()

    def download_file(self):
        file_path = os.path.join(tempfile.gettempdir(), self.service_name, 'received', self.task_hash, self.sha256)
        if not os.path.exists(file_path):
            raise Exception("File download failed. File not found on local filesystem.")

        received_sha256 = get_sha256_for_file(file_path)
        if received_sha256 != self.sha256:
            raise Exception(f"SHA256 mismatch between requested and downloaded file. {self.sha256} != {received_sha256}")

        return file_path

    def drop(self):
        self._result.drop_file = True

    def get_service_error(self):
        # Initialize a default service error
        error = Error()

        if not self.error_message:
            self.error_message = "Error message not provided"

        error.response.message = self.error_message
        error.response.service_name = self.service_name
        error.response.service_version = self.service_version
        error.response.service_tool_version = self.service_tool_version
        error.response.status = self.error_status
        error.sha256 = self.sha256
        error.type = self.error_type

        return error

    def get_service_result(self):
        self._result.classification = Classification.UNRESTRICTED  # TODO: calculate aggregate classification based on files, result sections, and tags
        self._result.response.service_name = self.service_name
        self._result.response.service_version = self.service_version
        self._result.response.service_tool_version = self.service_tool_version
        self._result.response.milestones.service_started = time.time()
        self._result.sha256 = self.sha256

        if self.extracted:
            self._result.response.extracted = self.extracted

        if self.supplementary:
            self._result.response.supplementary = self.supplementary

        return self._result

    def save_error(self, stack_info: str, recoverable: bool):
        self.error_message = stack_info

        if recoverable:
            self.error_status = 'FAIL_RECOVERABLE'
        else:
            self.error_status = 'FAIL_NONRECOVERABLE'

        error = self.get_service_error()
        error_path = os.path.join(self._working_directory, 'result.json')
        with open(error_path, 'wb') as f:
            json.dump(error.as_primitives(), f)
        self.log.info(f"Saving error to: {error_path}")

    def save_result(self):
        result = self.get_service_result()
        result_path = os.path.join(self._working_directory, 'result.json')
        with open(result_path, 'wb') as f:
            json.dump(result.as_primitives(), f)
        self.log.info(f"Saving result to: {result_path}")

    def set_oversized(self):
        self._result.oversized = True

    def set_service_context(self, context: str):
        self._result.response.service_context = context

    def set_result(self, result: Result):
        self._result.result = result or []

    def start(self, service_version, service_tool_version):
        self.service_version = service_version
        self.service_tool_version = service_tool_version

        self.clear_extracted()
        self.clear_supplementary()

    def success(self):
        self._result.response.milestones.service_completed = time.time()
        self.save_result()

    def working_directory(self):
        temp_dir = os.path.join(tempfile.gettempdir(), self.service_name.lower(), 'completed', self.task_hash)
        if not os.path.isdir(temp_dir):
            os.makedirs(temp_dir)
        if self._working_directory is None:
            self._working_directory = temp_dir
        return self._working_directory

