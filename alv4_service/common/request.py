import hashlib

from alv4_service.common.base import ServiceBase
from alv4_service.common.result import ResultBody
from alv4_service.common.task import Task


class ServiceRequest:
    def __init__(self, service: ServiceBase, task: Task) -> None:
        self._service = service
        self._working_directory = None
        self.sha256 = task.sha256
        self.sid = task.sid
        self.task = task
        self.task_hash = hashlib.md5((str(self.task.sid + self.sha256).encode('utf-8'))).hexdigest()


    def add_extracted(self, path, name, description, classification=None):
        """
        Add an extracted file for additional processing.

        :param path: Complete path to the extracted file
        :param name: Display name of the extracted file
        :param description: Descriptive text about the extracted file
        :param classification: Classification of the extracted file (default: service classification)
        :return: None
        """

        self.task.add_extracted(path, name, description, classification)

    def add_supplementary(self, path, name, description, classification=None):
        """
        Add a supplementary file.

        :param path: Complete path to the supplementary file
        :param name: Display name of the supplementary file
        :param description: Descriptive text about the supplementary file
        :param classification: Classification of the supplementary file (default: service classification)
        :return: None
        """

        self.task.add_supplementary(path, name, description, classification)

    @property
    def download_file(self):
        return self.task.download_file()

    def drop(self):
        self.task.drop()

    @property
    def result(self) -> ResultBody:
        return self.task.result.as_primitives()

    @result.setter
    def result(self, result: ResultBody):
        self.task.result = result

    def set_service_context(self, context):
        self.task.set_service_context(context)

    @property
    def working_directory(self):
        return self.task.working_directory()