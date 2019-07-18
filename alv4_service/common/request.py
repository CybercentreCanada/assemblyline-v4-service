# from __future__ import annotations
import logging

from alv4_service.common.result import Result
from alv4_service.common.task import Task
from assemblyline.common import forge
from assemblyline.common import log as al_log

# CLASSIFICATION = helper.get_classification()
CLASSIFICATION = forge.get_classification()


class ServiceRequest:
    def __init__(self, task: Task) -> None:
        # Initialize logging for the service
        al_log.init_logging(f'{task.service_name}', log_level=logging.INFO)
        self.log = logging.getLogger(f'assemblyline.service.{task.service_name.lower()}')

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
    def result(self, result: Result) -> None:
        self.task.result = result.finalize()

    def set_service_context(self, context) -> None:
        self.task.set_service_context(context)

    @property
    def working_directory(self) -> str:
        return self.task.working_directory()
