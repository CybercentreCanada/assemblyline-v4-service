import json
import logging
import os
import tempfile
from typing import Any, Dict, List, Optional, Union

from assemblyline_v4_service.common.api import PrivilegedServiceAPI, ServiceAPI
from assemblyline_v4_service.common.helper import get_service_manifest
from assemblyline_v4_service.common.result import Result

from assemblyline.common import forge
from assemblyline.common.constants import MAX_INT
from assemblyline.common import log as al_log
from assemblyline.common.classification import Classification
from assemblyline.common.digests import get_digests_for_file, get_sha256_for_file
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.str_utils import StringTable
from assemblyline.odm.messages.task import Task as ServiceTask

PARENT_RELATION = StringTable('PARENT_RELATION', [
    ('ROOT', 0),
    ('EXTRACTED', 1),
    ('INFORMATION', 2),
    ('DYNAMIC', 3),
    ('MEMDUMP', 4),
    ('DOWNLOADED', 5),
])


class MaxExtractedExceeded(Exception):
    pass


class Task:
    def __init__(self, task: ServiceTask):
        # Initialize logging
        al_log.init_logging(f'{task.service_name.lower()}', log_level=logging.INFO)
        self.log = logging.getLogger(f'assemblyline.service.{task.service_name.lower()}')

        tags = {}
        uses_tag_score = False

        # Option for data integrity assurance rather than performance
        # if task.tags and all(isinstance(tag.score, int) for tag in task.tags):

        if task.tags and isinstance(task.tags[0].score, int):
            uses_tag_score = True

        for t in task.tags:
            tags.setdefault(t.type, [])
            data = t.value
            if uses_tag_score:
                data = (t.value, t.score)
            tags[t.type].append(data)

        self._classification: Classification = forge.get_classification()
        self._service_completed: Optional[str] = None
        self._service_started: Optional[str] = None
        self._working_directory: Optional[str] = None
        self.deep_scan = task.deep_scan
        self.depth = task.depth
        self.drop_file: bool = False
        self.error_message: Optional[str] = None
        self.error_status: Optional[str] = None
        self.error_type: str = 'EXCEPTION'
        self.extracted: List[Dict[str, str]] = []
        self.file_name = task.filename
        self.fileinfo = task.fileinfo
        self.ignore_filtering = task.ignore_filtering
        self.min_classification = task.min_classification.value
        self.max_extracted = task.max_files
        self.metadata = task.metadata
        self.partial_result: bool = False
        self.result: Result = Result()
        self.safelist_config: Dict[str, Any] = task.safelist_config
        self.service_config: Dict[str, Any] = dict(task.service_config)
        self.service_context: Optional[str] = None
        self.service_debug_info: Optional[str] = None
        self.service_default_result_classification = None
        self.service_name: str = task.service_name
        self.service_tool_version: Optional[str] = None
        self.service_version: Optional[str] = None
        self.sid: str = task.sid
        self.supplementary: List[Dict[str, str]] = []
        self.tags = tags
        self.temp_submission_data: Dict[str, Any] = {
            row.name: row.value for row in task.temporary_submission_data
        }

    def _add_file(self, path: str, name: str, description: str,
                  classification: Optional[Classification] = None,
                  is_section_image: bool = False,
                  is_supplementary: bool = False,
                  allow_dynamic_recursion: bool = False,
                  parent_relation: str = PARENT_RELATION.EXTRACTED) -> Optional[Dict[str, str]]:
        # Reject empty files
        if os.path.getsize(path) == 0:
            self.log.info(f"Adding empty extracted or supplementary files is not allowed. "
                          f"Empty file ({name}) was ignored.")
            return
        elif os.path.getsize(path) > MAX_INT:
            self.log.error(f"Adding file of size {os.path.getsize(path)} is impossible due to ElasticSearch "
                           f"limitations. File ({name}) was ignored.")
            return

        if parent_relation not in PARENT_RELATION.keys():
            raise ValueError(
                (
                    f"An invalid 'parent_relation' was provided: '{parent_relation}'. "
                    f"Possible values are: '{PARENT_RELATION.keys()}'"
                )
            )

        # If file classification not provided, then use the default result classification
        if not classification:
            classification = self.service_default_result_classification

        file = dict(
            name=name,
            sha256=get_sha256_for_file(path),
            description=description,
            classification=self._classification.max_classification(self.min_classification, classification),
            path=path,
            is_section_image=is_section_image,
            is_supplementary=is_supplementary,
            allow_dynamic_recursion=allow_dynamic_recursion,
            parent_relation=parent_relation
        )

        return file

    def add_extracted(self, path: str, name: str, description: str,
                      classification: Optional[Classification] = None,
                      safelist_interface: Optional[Union[ServiceAPI, PrivilegedServiceAPI]] = None,
                      allow_dynamic_recursion: bool = False, parent_relation: str = PARENT_RELATION.EXTRACTED) -> bool:

        # Service-based safelisting of files has to be configured at the global configuration
        # Allows the administrator to be selective about the types of hashes to lookup in the safelist
        if safelist_interface and self.safelist_config.enabled and not (self.deep_scan or self.ignore_filtering):
            # Ignore adding files that are known to the system to be safe
            digests = get_digests_for_file(path, calculate_entropy=False, skip_fuzzy_hashes=True)
            for hash_type in self.safelist_config.hash_types:
                qhash = digests[hash_type]
                resp = safelist_interface.lookup_safelist(qhash)
                self.log.debug(f'Checking system safelist for {hash_type}: {qhash}')
                if resp and resp['enabled'] and resp['type'] == 'file':
                    self.log.info(f'Dropping safelisted, extracted file.. ({hash_type}: {qhash})')
                    return False

        if self.max_extracted and len(self.extracted) >= int(self.max_extracted):
            raise MaxExtractedExceeded

        if not path:
            raise ValueError("Path cannot be empty")

        if not name:
            raise ValueError("Name cannot be empty")

        if not description:
            raise ValueError("Description cannot be empty")

        file = self._add_file(path, name, description, classification,
                              allow_dynamic_recursion=allow_dynamic_recursion,
                              parent_relation=parent_relation)

        if not file:
            return False

        self.extracted.append(file)
        return True

    def add_supplementary(
        self, path: str, name: str, description: str,
        classification: Optional[Classification] = None,
        is_section_image: bool = False,
        parent_relation: str = PARENT_RELATION.INFORMATION
    ) -> Optional[dict]:
        if not path:
            raise ValueError("Path cannot be empty")

        if not name:
            raise ValueError("Name cannot be empty")

        if not description:
            raise ValueError("Description cannot be empty")

        file = self._add_file(path, name, description, classification, is_section_image,
                              is_supplementary=True, parent_relation=parent_relation)

        if not file:
            return None

        self.supplementary.append(file)
        return file

    def clear_extracted(self) -> None:
        self.extracted.clear()

    def clear_supplementary(self) -> None:
        self.supplementary.clear()

    def drop(self) -> None:
        self.drop_file = True

    def get_param(self, name: str) -> Any:
        param = self.service_config.get(name, None)
        if param is not None:
            return param
        else:
            # Check service manifest commited to disk and use param's default, if it exists.
            for s_param in get_service_manifest().get('config', {}).get('submission_params', []):
                if s_param.get('name') == name:
                    return s_param['default']
            raise Exception(f"Service submission parameter not found: {name}")

    def get_service_error(self) -> Dict[str, Any]:
        error = dict(
            response=dict(
                message=self.error_message,
                service_name=self.service_name,
                service_version=self.service_version,
                service_tool_version=self.service_tool_version,
                status=self.error_status,
            ),
            sha256=self.sha256,
            type=self.error_type,
        )

        return error

    def get_service_result(self) -> Dict[str, Any]:
        # Default result classification
        classification = self._classification.max_classification(self.min_classification,
                                                                 self.service_default_result_classification)

        # Finalise results
        result_obj = self.result.finalize()

        # Loop through results to aggregate classification
        for section in result_obj['sections']:
            classification = self._classification.max_classification(classification, section['classification'])

        # Loop through extracted files to aggregate classification
        for ext_file in self.extracted:
            classification = self._classification.max_classification(classification, ext_file['classification'])

        result = dict(
            classification=classification,
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
            result=result_obj,
            sha256=self.sha256,
            type=self.file_type,
            size=self.file_size,
            drop_file=self.drop_file,
            partial=self.partial_result,
            temp_submission_data=self.temp_submission_data,
        )

        return result

    def partial(self) -> None:
        self.partial_result = True

    def save_error(self, stack_info: str, recoverable: bool) -> None:
        self.error_message = stack_info

        if recoverable:
            self.error_status = 'FAIL_RECOVERABLE'
        else:
            self.error_status = 'FAIL_NONRECOVERABLE'

        error = self.get_service_error()
        error_path = os.path.join(
            os.environ.get('TASKING_DIR', tempfile.gettempdir()),
            f'{self.sid}_{self.sha256}_error.json')
        with open(error_path, 'w') as f:
            json.dump(error, f, default=str)
        self.log.info(f"[{self.sid}] Saving error to: {error_path}")

    def save_result(self) -> None:
        result = self.get_service_result()
        result_path = os.path.join(
            os.environ.get('TASKING_DIR', tempfile.gettempdir()),
            f'{self.sid}_{self.sha256}_result.json')
        with open(result_path, 'w') as f:
            json.dump(result, f, default=str)
        self.log.info(f"[{self.sid}] Saving result to: {result_path}")

    def set_service_context(self, context: str) -> None:
        self.service_context = context

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

    def validate_file(self) -> str:
        file_path = os.path.join(os.environ.get('TASKING_DIR', tempfile.gettempdir()), self.sha256)
        if not os.path.exists(file_path):
            raise Exception("File download failed. File not found on local filesystem.")

        received_sha256 = get_sha256_for_file(file_path)
        if received_sha256 != self.sha256:
            raise Exception(f"SHA256 mismatch between requested and "
                            f"downloaded file. {self.sha256} != {received_sha256}")

        return file_path

    @property
    def working_directory(self) -> str:
        temp_dir = os.path.join(os.environ.get('TASKING_DIR', tempfile.gettempdir()), 'working_directory')
        if not os.path.isdir(temp_dir):
            os.makedirs(temp_dir)
        if self._working_directory is None:
            self._working_directory = tempfile.mkdtemp(dir=temp_dir)
        return self._working_directory

    @property
    def file_type(self) -> str:
        return self.fileinfo.type

    @property
    def file_size(self) -> int:
        return self.fileinfo.size

    @property
    def md5(self) -> str:
        return self.fileinfo.md5

    @property
    def mime(self) -> str:
        return self.fileinfo.mime or None

    @property
    def sha1(self) -> str:
        return self.fileinfo.sha1

    @property
    def sha256(self) -> str:
        return self.fileinfo.sha256

    # Duplicate of file_type for backward compatibility
    @property
    def type(self) -> str:
        return self.fileinfo.type
