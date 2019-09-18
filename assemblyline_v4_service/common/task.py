import json
import logging
import os
import shutil
import tempfile
from typing import List, Optional, Any, Dict

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.common.classification import Classification
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.error import Error


class Task:
    def __init__(self, task: ServiceTask):
        # Initialize logging
        al_log.init_logging(f'{task.service_name.lower()}', log_level=logging.INFO)
        self.log = logging.getLogger(f'assemblyline.service.{task.service_name.lower()}')

        self._classification: Classification = forge.get_classification()
        self._service_completed: Optional[str] = None
        self._service_started: Optional[str] = None
        self._working_directory: Optional[str] = None
        self.drop_file: bool = False
        self.error_message: Optional[str] = None
        self.error_status: Optional[str] = None
        self.error_type: str = 'EXCEPTION'
        self.extracted: List[Dict[str, str]] = []
        self.file_type = task.fileinfo.type
        self.md5: str = task.fileinfo.md5
        self.result: Optional[Dict[str, Any]] = None
        self.service_config: Dict[str, Any] = dict(task.service_config)
        self.service_context: Optional[str] = None
        self.service_debug_info: Optional[str] = None
        self.service_default_result_classification = None
        self.service_name: str = task.service_name
        self.service_tool_version: Optional[str] = None
        self.service_version: Optional[str] = None
        self.sha1: str = task.fileinfo.sha1
        self.sha256: str = task.fileinfo.sha256
        self.sid: str = task.sid
        self.supplementary: List[Dict[str, str]] = []
        self.ttl: int = task.ttl
        self.type: str = task.fileinfo.type

    def _add_file(self, path: str, name: str, description: str, classification: Optional[Classification] = None):
        # Reject empty files
        if os.path.getsize(path) == 0:
            self.log.warning(f"Adding empty extracted or supplementary files is not allowed. "
                             f"Empty file ({name}) was ignored.")
            return

        # If file classification not provided, then use the default result classification
        if not classification:
            classification = self.service_default_result_classification

        # Move file to base of working directory
        file_path = os.path.join(self._working_directory, name)
        if not os.path.exists(file_path):
            shutil.move(path, file_path)

        file = dict(
            name=name,
            sha256=get_sha256_for_file(file_path),
            description=description,
            classification=classification,
        )

        return file

    def add_extracted(self, path: str, name: str, description: str, classification: Optional[Classification] = None):
        file = self._add_file(path, name, description, classification)

        self.extracted.append(file)

    def add_supplementary(self, path: str, name: str, description: str, classification: Optional[Classification] = None):
        file = self._add_file(path, name, description, classification)

        self.supplementary.append(file)

    def clear_extracted(self) -> None:
        self.extracted.clear()

    def clear_supplementary(self) -> None:
        self.supplementary.clear()

    def download_file(self) -> str:
        file_path = os.path.join(tempfile.gettempdir(), self.service_name.lower(), 'received', self.sha256)
        if not os.path.exists(file_path):
            raise Exception("File download failed. File not found on local filesystem.")

        received_sha256 = get_sha256_for_file(file_path)
        if received_sha256 != self.sha256:
            raise Exception(f"SHA256 mismatch between requested and downloaded file. {self.sha256} != {received_sha256}")

        return file_path

    def drop(self) -> None:
        self.drop_file = True

    def get_param(self, name: str) -> Any:
        param = self.service_config.get(name, None)
        if param is not None:
            return param
        else:
            raise Exception(f"Service submission parameter not found: {name}")

    def get_service_error(self) -> Error:
        error = Error(dict(
            created=now_as_iso(),
            expiry_ts=now_as_iso(self.ttl * 24 * 60 * 60),
            response=dict(
                message=self.error_message,
                service_name=self.service_name,
                service_version=self.service_version,
                service_tool_version=self.service_tool_version,
                status=self.error_status,
            ),
            sha256=self.sha256,
            type=self.error_type,
        ))

        return error

    def get_service_result(self) -> Dict[str, Any]:
        result = dict(
            classification=self._classification.UNRESTRICTED,  # TODO: calculate aggregate classification based on files, result sections, and tags
            created=now_as_iso(),
            expiry_ts=now_as_iso(self.ttl * 24 * 60 * 60),
            response=dict(
                milestones=dict(
                    service_started=self._service_started,
                    service_completed=self._service_completed,
                ),
                service_version=self.service_version,
                service_name=self.service_name,
                service_tool_version=self.service_tool_version,
                supplementary=self.supplementary,
                extracted=self.extracted,
                service_context=self.service_context,
                service_debug_info=self.service_debug_info,
            ),
            result=self.result,
            sha256=self.sha256,
            drop_file=self.drop_file,
        )

        return result

    def save_error(self, stack_info: str, recoverable: bool) -> None:
        self.error_message = stack_info

        if recoverable:
            self.error_status = 'FAIL_RECOVERABLE'
        else:
            self.error_status = 'FAIL_NONRECOVERABLE'

        error = self.get_service_error()
        error_path = os.path.join(self._working_directory, 'result.json')
        with open(error_path, 'wb') as f:
            json.dump(error.as_primitives().decode(), f)
        self.log.info(f"Saving error to: {error_path}")

    def save_result(self) -> None:
        result = self.get_service_result()
        result_path = os.path.join(self._working_directory, 'result.json')
        with open(result_path, 'w') as f:
            json.dump(result, f)
        self.log.info(f"Saving result to: {result_path}")

    def set_service_context(self, context: str) -> None:
        self.service_context = context

    def set_result(self, result: Dict[str, Any]) -> None:
        self.result = result

    def start(self, service_default_result_classification: Classification,
              service_version: str, service_tool_version: Optional[str] = None) -> None:
        self.service_version = service_version
        self.service_tool_version = service_tool_version
        self.service_default_result_classification = service_default_result_classification

        self._service_started = now_as_iso()

        self.clear_extracted()
        self.clear_supplementary()

    def success(self) -> None:
        self._service_completed = now_as_iso()
        self.save_result()

    def working_directory(self) -> str:
        temp_dir = os.path.join(tempfile.gettempdir(), self.service_name.lower(), 'completed')
        if not os.path.isdir(temp_dir):
            os.makedirs(temp_dir)
        if self._working_directory is None:
            self._working_directory = temp_dir
        return self._working_directory
