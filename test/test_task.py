import tempfile
from logging import Logger

import pytest
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.task import *

from assemblyline.odm.messages.task import DataItem, TagItem
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.config import ServiceSafelist


@pytest.fixture
def servicetask():
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
    return st


def test_task_init(servicetask):
    t = Task(servicetask)

    # Defaults
    assert isinstance(t.log, Logger)
    assert isinstance(t._classification, Classification)
    assert t._service_completed is None
    assert t._service_started is None
    assert t._working_directory is None
    assert t.deep_scan is False
    assert t.depth == 0
    assert t.drop_file is False
    assert t.error_message is None
    assert t.error_status is None
    assert t.error_type == 'EXCEPTION'
    assert t.extracted == []
    assert t.file_name == "blah"
    assert t.file_type == "text/plain"
    assert t.file_size == 0
    assert t.ignore_filtering is False
    assert t.min_classification == "TLP:C"
    assert t.max_extracted == 0
    assert t.metadata == {}
    assert t.md5 == "d41d8cd98f00b204e9800998ecf8427e"
    assert t.mime is None
    assert t.result is None
    assert isinstance(t.safelist_config, ServiceSafelist)
    assert t.service_config == {}
    assert t.service_context is None
    assert t.service_debug_info is None
    assert t.service_default_result_classification is None
    assert t.service_name == "blah"
    assert t.service_tool_version is None
    assert t.service_version is None
    assert t.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert t.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert isinstance(t.sid, str)
    assert t.supplementary == []
    assert t.tags == {}
    assert t.temp_submission_data == {}
    assert t.type == "text/plain"

    # Tags with no score, temp_submission_data
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
        # No tag score
        "tags": [
            TagItem({"type": "blah.blah", "value": "blah1", "short_type": "blah"}),
            TagItem({"type": "blah.blah", "value": "blah2", "short_type": "blah"}),
        ],
        "temporary_submission_data": [
            DataItem({"name": "a", "value": "b"}),
            DataItem({"name": "c", "value": "d"}),
        ]
    })
    t = Task(st)
    assert t.tags == {'blah.blah': ['blah1', 'blah2']}
    assert t.temp_submission_data == {'a': 'b', 'c': 'd'}

    # Tags with score
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
        # No tag score
        "tags": [
            TagItem({"type": "blah.blah", "value": "blah1", "short_type": "blah", "score": 123}),
            TagItem({"type": "blah.blah", "value": "blah2", "short_type": "blah", "score": 321}),
        ],
    })
    t = Task(st)
    assert t.tags == {'blah.blah': [('blah1', 123), ('blah2', 321)]}


def test_task_add_file(servicetask):
    t = Task(servicetask)
    _, path = tempfile.mkstemp()

    # Empty file
    assert t._add_file(path, "name", "description") is None

    with open(path, "w") as f:
        f.write("test")

    # File is not empty
    assert t._add_file(path, "name", "description") == {'name': 'name', 'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'description': 'description', 'classification': 'TLP:C', 'path': path, 'is_section_image': False, 'allow_dynamic_recursion': False, 'parent_relation': 'EXTRACTED'}

    # Non-defaults
    assert t._add_file(
        path, "name", "description", classification="TLP:AMBER",
        allow_dynamic_recursion=True, parent_relation="DYNAMIC"
    ) == {'name': 'name', 'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'description': 'description', 'classification': 'TLP:C', 'path': path, 'is_section_image': False, 'allow_dynamic_recursion': True, 'parent_relation': 'DYNAMIC'}


def test_task_add_extracted(servicetask, mocker):
    t = Task(servicetask)
    _, path = tempfile.mkstemp()

    # MaxExtractedExceeded
    t.max_extracted = -1
    with pytest.raises(MaxExtractedExceeded):
        t.add_extracted(None, None, None)

    t.max_extracted = 10

    # No path
    with pytest.raises(ValueError):
        t.add_extracted(None, "name", "description")

    # No name
    with pytest.raises(ValueError):
        t.add_extracted(path, None, "description")

    # No description
    with pytest.raises(ValueError):
        t.add_extracted(path, "name", None)

    # Empty file
    assert t.add_extracted(path, "name", "description") is False

    with open(path, "w") as f:
        f.write("test")

    # Safelisted file hash
    service_attributes = helper.get_service_attributes()
    sa = ServiceAPI(service_attributes, None)
    with mocker.patch.object(sa, "lookup_safelist", return_value={"enabled": True, "type": "file"}) as m:
        t.safelist_config.enabled = True
        assert t.add_extracted(path, "name", "description", safelist_interface=sa) is False

    # A valid extracted file!
    assert t.add_extracted(path, "name", "description") is True
    assert t.extracted == [{'name': 'name', 'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'description': 'description', 'classification': 'TLP:C', 'path': path, 'is_section_image': False, 'allow_dynamic_recursion': False, 'parent_relation': 'EXTRACTED'}]


def test_task_add_supplementary(servicetask):
    t = Task(servicetask)
    _, path = tempfile.mkstemp()

    # No path
    with pytest.raises(ValueError):
        t.add_supplementary(None, "name", "description")

    # No name
    with pytest.raises(ValueError):
        t.add_supplementary(path, None, "description")

    # No description
    with pytest.raises(ValueError):
        t.add_supplementary(path, "name", None)

    # Empty file
    assert t.add_supplementary(path, "name", "description") is None

    with open(path, "w") as f:
        f.write("test")

    assert t.add_supplementary(path, "name", "description") == {'name': 'name', 'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'description': 'description', 'classification': 'TLP:C', 'path': path, 'is_section_image': False, 'allow_dynamic_recursion': False, 'parent_relation': 'EXTRACTED'}
    assert t.supplementary == [{'name': 'name', 'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'description': 'description', 'classification': 'TLP:C', 'path': path, 'is_section_image': False, 'allow_dynamic_recursion': False, 'parent_relation': 'EXTRACTED'}]


def test_task_clear_extracted(servicetask):
    t = Task(servicetask)
    _, path = tempfile.mkstemp()
    with open(path, "w") as f:
        f.write("test")

    t.add_extracted(path, "name", "description")
    assert len(t.extracted) == 1
    assert t.clear_extracted() is None
    assert t.extracted == []


def test_task_clear_supplementary(servicetask):
    t = Task(servicetask)
    _, path = tempfile.mkstemp()
    with open(path, "w") as f:
        f.write("test")

    t.add_supplementary(path, "name", "description")
    assert len(t.supplementary) == 1
    assert t.clear_supplementary() is None
    assert t.supplementary == []


def test_task_drop(servicetask):
    t = Task(servicetask)
    assert t.drop_file is False
    assert t.drop() is None
    assert t.drop_file is True


def test_task_get_param(servicetask):
    t = Task(servicetask)
    # Submission parameter does not exist
    with pytest.raises(Exception):
        t.get_param("blah")

    # Submission parameter exists
    t.service_config = {"blah":"blah"}
    assert t.get_param("blah") == "blah"

    # Submission parameter does not exist in service_config but
    # it does in the service_manifest on disk
    t.service_config = {}
    print(get_service_manifest().get('config', {}).get('submission_params', []))
    assert t.get_param("thing") == "blah"
