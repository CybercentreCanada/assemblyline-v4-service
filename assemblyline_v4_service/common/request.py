import logging
import hashlib
import tempfile
from typing import Any, Dict, List, Optional, TextIO, Union

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.common.file import make_uri_file
from assemblyline.common.classification import Classification
from PIL import Image

from assemblyline_v4_service.common.api import PrivilegedServiceAPI, ServiceAPI
from assemblyline_v4_service.common.ocr import ocr_detections
from assemblyline_v4_service.common.result import Heuristic, Result, ResultKeyValueSection
from assemblyline_v4_service.common.task import MaxExtractedExceeded, Task
from assemblyline_v4_service.common.utils import extract_passwords

CLASSIFICATION = forge.get_classification()
WEBP_MAX_SIZE = 16383


class ServiceRequest:
    def __init__(self, task: Task) -> None:
        # Initialize logging for the service
        al_log.init_logging(f'{task.service_name}', log_level=logging.INFO)
        self.log = logging.getLogger(f'assemblyline.service.{task.service_name.lower()}')

        self._working_directory = task.working_directory
        self._file_path = None
        self.task = task

    def add_extracted(self, path: str, name: str, description: str,
                      classification: Optional[Classification] = None,
                      safelist_interface: Optional[Union[ServiceAPI, PrivilegedServiceAPI]] = None,
                      allow_dynamic_recursion: bool = False, parent_relation: str = 'EXTRACTED') -> bool:
        """
        Add an extracted file for additional processing.

        :param path: Complete path to the extracted file
        :param name: Display name of the extracted file
        :param description: Descriptive text about the extracted file
        :param classification: Classification of the extracted file (default: service classification)
        :param safelist_interface: Safelisting interface provided by service. Used to filter extracted files.
        :param allow_dynamic_recursion: Allow this file to be analyzed during Dynamic Analysis even if
               Dynamic Recursion Prevention (DRP) is enabled.
        :param parent_relation: File relation to parent, if any.
        :return: None
        """

        try:
            r = self.task.add_extracted(path, name, description, classification,
                                        safelist_interface, allow_dynamic_recursion, parent_relation)
            return r
        except MaxExtractedExceeded:
            raise

    def add_extracted_uri(self, description: str, uri: str, params=None,
                          classification: Optional[Classification] = None, allow_dynamic_recursion: bool = False,
                          parent_relation: str = 'EXTRACTED') -> bool:
        if params:
            self.set_uri_metadata(uri, params)
        filepath = make_uri_file(self._working_directory, uri, params)
        return self.add_extracted(filepath, uri, description, classification=classification,
                                  allow_dynamic_recursion=allow_dynamic_recursion, parent_relation=parent_relation)

    def add_image(self, path: str, name: str, description: str,
                  classification: Optional[Classification] = None,
                  ocr_heuristic_id: Optional[int] = None, ocr_io: Optional[TextIO] = None) -> dict:
        """
        Add a image file to be viewed in the result section.

        :param path: Complete path to the image file
        :param name: Display name of the image file
        :param description: Descriptive text about the image file
        :param classification: Classification of the image file (default: service classification)
        :param ocr_heuristic_id: Heuristic ID associated to suspicious OCR detections
        :param ocr_io: Stream to write the raw OCR output to
        :return: None
        """

        outtmp = tempfile.NamedTemporaryFile(dir=self._working_directory, delete=False)
        data = {}
        with tempfile.NamedTemporaryFile(dir=self._working_directory, delete=False) as thumbtmp:
            # Load Image
            img = Image.open(path)

            # Force image format switch to prevent exploit to cross-over
            img_format = 'WEBP'
            if img.format == img_format:
                img_format = 'PNG'

            if img_format == "WEBP" and (img.height > WEBP_MAX_SIZE or img.width > WEBP_MAX_SIZE):
                # Maintain aspect ratio
                img.thumbnail((WEBP_MAX_SIZE, WEBP_MAX_SIZE), Image.LANCZOS)

            # Save and upload new image
            try:
                img.save(outtmp.name, format=img_format)

                img_res = self.task.add_supplementary(outtmp.name, name, description, classification,
                                                      is_section_image=True)

                # Save and upload thumbnail
                img.thumbnail((128, 128))
                img.save(thumbtmp.name, format=img_format, optimize=True)
                thumb_res = self.task.add_supplementary(thumbtmp.name, f"{name}.thumb",
                                                        f"{description} (thumbnail)", classification,
                                                        is_section_image=True)
                data = {'img': {k: v for k, v in img_res.items() if k in ['name', 'description', 'sha256']},
                        'thumb': {k: v for k, v in thumb_res.items() if k in ['name', 'description', 'sha256']}}
            except ValueError as e:
                if e.args and e.args[0] == 'buffer is not large enough':
                    self.log.warning('Unable to convert image to PNG/WEBP formats..')

        if ocr_heuristic_id:
            detections = {}
            try:
                detections = ocr_detections(path, ocr_io)
            except ImportError as e:
                self.log.warning(str(e))
            except (SystemError, TypeError, RuntimeError):
                # If we encounter a system error with the original file, attempt OCR with alternative format (WEBP, PNG)
                try:
                    detections = ocr_detections(outtmp.name, ocr_io)
                except (SystemError, RuntimeError):
                    # If we encountered a system error, then let OCR analysis go
                    # This shouldn't affect service analysis
                    pass

            if detections:
                # If we were able to detect potential passwords, add it to the submission's password list
                if detections.get('password'):
                    pw_list = set(self.temp_submission_data.get('passwords', []))
                    [pw_list.update(extract_passwords(pw_string)) for pw_string in detections['password']]
                    self.temp_submission_data['passwords'] = sorted(pw_list)

                heuristic = Heuristic(ocr_heuristic_id, signatures={
                    f'{k}_strings': len(v) for k, v in detections.items()})
                ocr_section = ResultKeyValueSection(f'Suspicious strings found during OCR analysis on file {name}')
                ocr_section.set_heuristic(heuristic)
                for k, v in detections.items():
                    ocr_section.set_item(k, v)
                data['ocr_section'] = ocr_section

        return data

    def add_supplementary(self, path: str, name: str, description: str,
                          classification: Optional[Classification] = None) -> bool:
        """
        Add a supplementary file.

        :param path: Complete path to the supplementary file
        :param name: Display name of the supplementary file
        :param description: Descriptive text about the supplementary file
        :param classification: Classification of the supplementary file (default: service classification)
        :return: None
        """

        return self.task.add_supplementary(path, name, description, classification)

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
        if not self._file_path:
            self._file_path = self.task.validate_file()
        return self._file_path

    @property
    def file_contents(self):
        """
        Returns the content of the file for analysis.

        :return: Contents of the file
        """
        file_path = self.file_path
        with open(file_path, "rb") as fh:
            return fh.read()

    def get_param(self, name: str):
        """
        Get a submission parameter.

        :return: Value of the requested submission parameter
        """
        return self.task.get_param(name)

    @property
    def result(self) -> Result:
        """
        Get the current Result as set by the service.

        :return: Current Result object as set by the service
        """
        return self.task.result

    @result.setter
    def result(self, result: Result) -> None:
        """
        Set the result.

        :param result: Result object created by the service
        """
        self.task.result = result

    def set_service_context(self, context) -> None:
        """
        Set the service context.

        :param context: Context of the service
        """
        self.task.set_service_context(context)

    def set_uri_metadata(self, uri: str, params: Dict[str, Any] = None):
        md5hash = hashlib.md5(uri.encode()).hexdigest()
        self.temp_submission_data[f"uri_metadata_{md5hash}"] = params

    def get_uri_metadata(self, uri: str) -> Dict[str, Any]:
        md5hash = hashlib.md5(uri.encode()).hexdigest()
        return self.temp_submission_data.get(f"uri_metadata_{md5hash}", None)

    @property
    def temp_submission_data(self) -> Dict[str, Any]:
        """
        Get the temporary submission data as set by the service in parent task(s) and current task.

        :return: Current temporary submission data
        """
        return self.task.temp_submission_data

    @temp_submission_data.setter
    def temp_submission_data(self, data: Dict[str, Any]) -> None:
        """
        Set the temporary submission data, replacing any previous data.

        :param data: Temporary submission data
        """
        self.task.temp_submission_data = data

    @property
    def deep_scan(self) -> bool:
        return self.task.deep_scan

    @property
    def extracted(self) -> List[Dict[str, str]]:
        return self.task.extracted

    @property
    def file_name(self) -> str:
        return self.task.file_name

    @property
    def file_type(self) -> str:
        return self.task.fileinfo.type

    @property
    def file_size(self) -> int:
        return self.task.fileinfo.size

    @property
    def max_extracted(self) -> int:
        return self.task.max_extracted

    @property
    def md5(self) -> str:
        return self.task.fileinfo.md5

    @property
    def sha1(self) -> str:
        return self.task.fileinfo.sha1

    @property
    def sha256(self) -> str:
        return self.task.fileinfo.sha256

    @property
    def sid(self) -> str:
        return self.task.sid

    @property
    def ssdeep(self) -> str:
        return self.task.fileinfo.ssdeep

    @property
    def tlsh(self) -> str:
        return self.task.fileinfo.tlsh
