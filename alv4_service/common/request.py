import hashlib
import os
import tempfile

from alv4_service.common.base import ServiceBase
from alv4_service.common.task import Task
from assemblyline.common.digests import get_sha256_for_file


class ServiceRequest(object):
    def __init__(self, service: ServiceBase, task: Task) -> None:
        self._service = service
        self.sha256 = task.sha256
        self.sid = task.sid
        self.task = task

    def add_extracted(self, name, description, sha256=None, classification=None):

        return self.task.add_extracted(name, description, sha256, classification)

    def add_supplementary(self, name, description, sha256=None, classification=None):

        return self.task.add_supplementary(name, description, sha256, classification)

    def download(self):
        task_hash = hashlib.md5((str(self.task.sid + self.sha256).encode('utf-8'))).hexdigest()
        file_path = os.path.join(tempfile.gettempdir(), self._service.service.name.lower(), 'received', task_hash,
                                 self.sha256)
        if not os.path.exists(file_path):
            print('File not found locally, downloading again')
        if not os.path.exists(file_path):
            raise Exception('Download failed. Not found on local filesystem')

        received_sha256 = get_sha256_for_file(file_path)
        if received_sha256 != self.sha256:
            raise Exception(f"SHA256 mismatch between requested and downloaded file. {self.sha256} != {received_sha256}")
        return file_path
