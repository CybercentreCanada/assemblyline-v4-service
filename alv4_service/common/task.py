import time

from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.result import Result, File


class Task(object):
    def __init__(self, task: ServiceTask):
        self._result = Result
        self.drop_file = False
        self.error_message = None
        self.error_status = None
        self.error_type = "EXCEPTION"
        self.extracted = []
        self.oversized = False
        self.result = []
        self.service_tool_version = None
        self.sha256 = task.fileinfo.sha256
        self.sid = task.sid
        self.supplementary = []
        self.task = task
        self.type = task.fileinfo.type

    def add_extracted(self, name, description, sha256, classification):
        # Initialize a default file
        file = File()

        file.classification = classification
        file.description = description
        file.name = name
        self.extracted.append(file)

    def add_supplementary(self, name, description, sha256, classification):
        # Initialize a default file
        file = File()

        file.classification = classification
        file.description = description
        file.name = name
        self.supplementary.append(file)

    def as_service_error(self, service):
        # Initialize a default service error
        error = Error()

        if not self.error_message:
            self.error_message = "Error message not provided"

        error.response.message = self.error_message
        error.response.service_name = service.name
        error.response.service_version = service.version
        error.response.service_tool_version = self.service_tool_version
        error.response.status = self.error_status
        error.sha256 = self.sha256
        error.type = self.error_type

        return error

    def as_service_result(self):
        if self.extracted:
            self._result.response.extracted = self.extracted

        if self.supplementary:
            self._result.response.supplementary = self.supplementary

        result.classification = self.classification
        result.drop_file = self.drop_file

        result.response.service_context = self.service_context
        result.response.service_tool_version = self.service_tool_version

        return self._result

    def clear_extracted(self):
        self.extracted = []

    def clear_supplementary(self):
        self.supplementary = []

    def set_oversized(self):
        self._result.oversized = True

    def set_result(self, result):
        self._result.result = result or []

    def start(self, service):
        self._result.response.milestones.service_started = time.time()
        self.clear_extracted()
        self.clear_supplementary()

        self._result.response.service_name = service.name
        self._result.response.service_version = service.version
        self._result.sha256 = self.sha256

    def success(self):
        self._result.response.milestones.service_completed = time.time()