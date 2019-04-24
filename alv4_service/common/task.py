from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.result import Result


class Task(object):
    def __init__(self, task: ServiceTask):
        self.extracted = []
        self.result = Result()
        self.service_completed = None
        self.service_started = None
        self.sha256 = task.fileinfo.sha256
        self.sid = task.sid
        self.supplementary = []
        self.type = task.fileinfo.type

    def as_service_result(self):
        # Initialize a default result
        result = Result()

        if not self.extracted:
            self.extracted = []
        if not self.supplementary:
            self.supplementary = []
        if not self.result:
            self.result = []

        result.classification = self.classification
        result.drop_file = self.drop_file
        result.oversized = self.oversized
        result.response.extracted = self.extracted
        result.response.milestones.service_started = self.service_started
        result.response.milestones.service_completed = self.service_completed
        result.response.service_context = self.service_context
        result.response.service_name = self.service_name
        result.response.service_version = self.service_version
        result.response.service_tool_version = self.service_tool_version
        result.response.supplementary = self.supplementary
        result.result = self.result
        result.sha256 = self.sha256

        return result

    def clear_extracted(self):
        self.extracted = []

    def clear_supplementary(self):
        self.supplementary = []

    def success(self):
        pass # TODO