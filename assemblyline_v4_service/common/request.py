import logging
from typing import Dict, Optional, Any

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.common.classification import Classification
from assemblyline_v4_service.common.result import Result
from assemblyline_v4_service.common.task import Task

CLASSIFICATION = forge.get_classification()


class ServiceRequest:
    def __init__(self, task: Task) -> None:
        # Initialize logging for the service
        al_log.init_logging(f'{task.service_name}', log_level=logging.INFO)
        self.log = logging.getLogger(f'assemblyline.service.{task.service_name.lower()}')

        self._working_directory = None
        self.file_type = task.file_type
        self.md5 = task.md5
        self.sha1 = task.sha1
        self.sha256 = task.sha256
        self.sid = task.sid
        self.task = task

    def add_extracted(self, path: str, name: str, description: str, classification: Optional[Classification] = None) -> None:
        """
        Add an extracted file for additional processing.

        :param path: Complete path to the extracted file
        :param name: Display name of the extracted file
        :param description: Descriptive text about the extracted file
        :param classification: Classification of the extracted file (default: service classification)
        :return: None
        """

        self.task.add_extracted(path, name, description, classification)

    def add_supplementary(self, path: str, name: str, description: str, classification: Optional[Classification] = None) -> None:
        """
        Add a supplementary file.

        :param path: Complete path to the supplementary file
        :param name: Display name of the supplementary file
        :param description: Descriptive text about the supplementary file
        :param classification: Classification of the supplementary file (default: service classification)
        :return: None
        """

        self.task.add_supplementary(path, name, description, classification)

    def drop(self) -> None:
        """
        Drop the task from further processing by other remaining service(s).

        :return: None
        """
        self.task.drop()

    @property
    def file_path(self) -> str:
        """
        Download the tasked file for analysis.

        :return: File path to the downloaded file
        """
        return self.task.download_file()

    def get_param(self, name: str):
        """
        Get a submission parameter.

        :return: Value of the requested submission parameter
        """
        return self.task.get_param(name)

    @property
    def result(self) -> Dict[str, Any]:
        """
        Get the current result as set by the service.

        :return: Current result as set by the service
        """
        return self.task.result.as_primitives()

    @result.setter
    def result(self, result: Result) -> None:
        """
        Set the result.

        :param result: Result object created by the service
        """
        self.task.result = result.finalize()

    def set_service_context(self, context) -> None:
        """
        Set the service context.

        :param context: Context of the service
        """
        self.task.set_service_context(context)

    @property
    def working_directory(self) -> str:
        """
        Get the temp working directory for the current task.

        :return: Temp directory path for the current task
        """
        return self.task.working_directory()
