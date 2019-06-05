from __future__ import annotations

from alv4_service.common import helper
from alv4_service.common.task import Task
from assemblyline.odm.models.result import ResultBody

CLASSIFICATION = helper.get_classification()


class ServiceRequest:
    def __init__(self, task: Task) -> None:
        self._working_directory = None
        self.md5 = task.md5
        self.sha1 = task.sha1
        self.sha256 = task.sha256
        self.sid = task.sid
        self.task = task

    def add_extracted(self, path: str, name: str, description: str, classification: CLASSIFICATION = None) -> None:
        """
        Add an extracted file for additional processing.

        :param path: Complete path to the extracted file
        :param name: Display name of the extracted file
        :param description: Descriptive text about the extracted file
        :param classification: Classification of the extracted file (default: service classification)
        :return: None
        """

        self.task.add_extracted(path, name, description, classification)

    def add_supplementary(self, path: str, name: str, description: str, classification: CLASSIFICATION = None) -> None:
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
    def download_file(self) -> str:
        return self.task.download_file()

    def drop(self) -> None:
        self.task.drop()

    @property
    def result(self) -> dict:
        return self.task.result.as_primitives()

    @result.setter
    def result(self, result: ResultBody) -> None:
        self.task.result = result

    def set_service_context(self, context) -> None:
        self.task.set_service_context(context)

    @property
    def working_directory(self) -> str:
        return self.task.working_directory()
