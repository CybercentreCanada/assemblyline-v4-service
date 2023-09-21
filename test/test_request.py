import os
import tempfile
from logging import Logger

import pytest
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import MaxExtractedExceeded, Task

from assemblyline.odm.messages.task import Task as ServiceTask


def test_init():
    st = ServiceTask({
        "service_config": {},
        "metadata": {},
        "min_classification": "",
        "fileinfo": {
            "magic": "blah",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "size": 0,
            "type": "text/plain",
        },
        "filename": "blah",
        "service_name": "blah",
        "max_files": 0,
    })
    t = Task(st)
    sr = ServiceRequest(t)
    assert isinstance(sr.log, Logger)
    assert os.path.exists(sr._working_directory)
    assert sr.deep_scan is False
    assert sr.extracted == []
    assert sr.file_name == "blah"
    assert sr.file_type == "text/plain"
    assert sr.file_size == 0
    assert sr._file_path is None
    assert sr.max_extracted == 0
    assert sr.md5 == "d41d8cd98f00b204e9800998ecf8427e"
    assert sr.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert sr.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert isinstance(sr.sid, str)
    assert isinstance(sr.task, Task)


def test_add_extracted():
    st = ServiceTask({
        "service_config": {},
        "metadata": {},
        "min_classification": "",
        "fileinfo": {
            "magic": "blah",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "size": 0,
            "type": "text/plain",
        },
        "filename": "blah",
        "service_name": "blah",
        "max_files": 0,
    })
    t = Task(st)
    sr = ServiceRequest(t)

    # Bare minimum, empty file is ignored
    _, path = tempfile.mkstemp()
    sr.add_extracted(path, "name", "description")
    assert sr.extracted == []

    with open(path, "w") as f:
        f.write("test")

    # Now the file is not empty
    sr.add_extracted(path, "name", "description")
    assert sr.extracted == [
        {
            'allow_dynamic_recursion': False,
            'classification': 'TLP:C',
            'description': 'description',
            'is_section_image': False,
            'name': 'name',
            'parent_relation': 'EXTRACTED',
            'path': path,
            'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
         },
    ]

    # Raise MaxExtractedExceeded
    sr.task.max_extracted = -1
    sr.extracted.clear()
    with pytest.raises(MaxExtractedExceeded):
        sr.add_extracted(path, "name", "description")
