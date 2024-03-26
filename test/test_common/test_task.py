import json
import os
import tempfile
from logging import Logger

import pytest
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.result import ResultSection
from assemblyline_v4_service.common.task import *

from assemblyline.odm.messages.task import DataItem, TagItem
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.config import ServiceSafelist


@pytest.fixture
def servicetask():
    st = ServiceTask(
        {
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
        }
    )
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
    assert t.error_type == "EXCEPTION"
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
    st = ServiceTask(
        {
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
            ],
        }
    )
    t = Task(st)
    assert t.tags == {"blah.blah": ["blah1", "blah2"]}
    assert t.temp_submission_data == {"a": "b", "c": "d"}

    # Tags with score
    st = ServiceTask(
        {
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
        }
    )
    t = Task(st)
    assert t.tags == {"blah.blah": [("blah1", 123), ("blah2", 321)]}


def test_task_add_file(servicetask):
    t = Task(servicetask)
    _, path = tempfile.mkstemp()

    # Empty file
    assert t._add_file(path, "name", "description") is None

    with open(path, "w") as f:
        f.write("test")

    # Incorrect parent_relation
    with pytest.raises(ValueError):
        t._add_file(path, "name", "description", parent_relation="BLAHBLAHBLAH") is None

    # File is not empty
    assert t._add_file(path, "name", "description") == {
        "name": "name",
        "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "description": "description",
        "classification": "TLP:C",
        "path": path,
        "is_section_image": False,
        "allow_dynamic_recursion": False,
        "parent_relation": "EXTRACTED",
    }

    # Non-defaults
    assert t._add_file(
        path, "name", "description", classification="TLP:AMBER", allow_dynamic_recursion=True, parent_relation="DYNAMIC"
    ) == {
        "name": "name",
        "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "description": "description",
        "classification": "TLP:C",
        "path": path,
        "is_section_image": False,
        "allow_dynamic_recursion": True,
        "parent_relation": "DYNAMIC",
    }


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
    assert t.extracted == [
        {
            "name": "name",
            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "description": "description",
            "classification": "TLP:C",
            "path": path,
            "is_section_image": False,
            "allow_dynamic_recursion": False,
            "parent_relation": "EXTRACTED",
        }
    ]


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

    assert t.add_supplementary(path, "name", "description") == {
        "name": "name",
        "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "description": "description",
        "classification": "TLP:C",
        "path": path,
        "is_section_image": False,
        "allow_dynamic_recursion": False,
        "parent_relation": "INFORMATION",
    }
    assert t.supplementary == [
        {
            "name": "name",
            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "description": "description",
            "classification": "TLP:C",
            "path": path,
            "is_section_image": False,
            "allow_dynamic_recursion": False,
            "parent_relation": "INFORMATION",
        }
    ]


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
    t.service_config = {"blah": "blah"}
    assert t.get_param("blah") == "blah"

    # Submission parameter does not exist in service_config but
    # it does in the service_manifest on disk
    t.service_config = {}
    assert t.get_param("thing") == "blah"


def test_task_get_service_error(servicetask):
    t = Task(servicetask)
    # Default
    assert t.get_service_error() == {
        "response": {
            "message": None,
            "service_name": "blah",
            "service_version": None,
            "service_tool_version": None,
            "status": None,
        },
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "EXCEPTION",
    }

    # Not default
    t.error_message = "error_message"
    t.service_version = "service_version"
    t.service_tool_version = "service_tool_version"
    t.error_status = "error_status"
    assert t.get_service_error() == {
        "response": {
            "message": "error_message",
            "service_name": "blah",
            "service_version": "service_version",
            "service_tool_version": "service_tool_version",
            "status": "error_status",
        },
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "EXCEPTION",
    }


def test_task_get_service_result(servicetask):
    t = Task(servicetask)
    t.result = Result()

    # Empty result
    assert t.get_service_result() == {
        "classification": "TLP:C",
        "response": {
            "milestones": {"service_started": None, "service_completed": None},
            "service_version": None,
            "service_name": "blah",
            "service_tool_version": None,
            "supplementary": [],
            "extracted": [],
            "service_context": None,
            "service_debug_info": None,
        },
        "result": {"score": 0, "sections": []},
        "partial": False,
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "text/plain",
        "size": 0,
        "drop_file": False,
        "temp_submission_data": {},
    }

    # Result with sections and extracted files that have differing classifications
    # Note that the max_classification method defaults to TLP:C in tests
    t.result.add_section(ResultSection("blah", classification="TLP:GREEN"))
    _, path = tempfile.mkstemp()
    with open(path, "w") as f:
        f.write("test")
    t.add_extracted(path, "name", "description", classification="TLP:AMBER")
    service_result = t.get_service_result()
    assert len(service_result["result"].pop("sections")) == 1
    assert service_result == {
        "classification": "TLP:C",
        "response": {
            "milestones": {"service_started": None, "service_completed": None},
            "service_version": None,
            "service_name": "blah",
            "service_tool_version": None,
            "supplementary": [],
            "extracted": [
                {
                    "allow_dynamic_recursion": False,
                    "classification": "TLP:C",
                    "description": "description",
                    "is_section_image": False,
                    "name": "name",
                    "parent_relation": "EXTRACTED",
                    "path": path,
                    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                }
            ],
            "service_context": None,
            "service_debug_info": None,
        },
        "result": {
            "score": 0,
        },
        "partial": False,
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "text/plain",
        "size": 0,
        "drop_file": False,
        "temp_submission_data": {},
    }


def test_task_save_error(servicetask):
    t = Task(servicetask)
    # Recoverable
    assert t.save_error("stack_info", True) is None
    assert t.error_status == "FAIL_RECOVERABLE"
    assert os.path.exists(f"/tmp/{t.sid}_{t.sha256}_error.json") is True
    assert json.loads(open(f"/tmp/{t.sid}_{t.sha256}_error.json", "r").read()) == {
        "response": {
            "message": "stack_info",
            "service_name": "blah",
            "service_version": None,
            "service_tool_version": None,
            "status": "FAIL_RECOVERABLE",
        },
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "EXCEPTION",
    }

    # Nonrecoverable
    assert t.save_error("stack_info", False) is None
    assert t.error_status == "FAIL_NONRECOVERABLE"
    assert os.path.exists(f"/tmp/{t.sid}_{t.sha256}_error.json") is True
    assert json.loads(open(f"/tmp/{t.sid}_{t.sha256}_error.json", "r").read()) == {
        "response": {
            "message": "stack_info",
            "service_name": "blah",
            "service_version": None,
            "service_tool_version": None,
            "status": "FAIL_NONRECOVERABLE",
        },
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "EXCEPTION",
    }

    os.remove(f"/tmp/{t.sid}_{t.sha256}_error.json")


def test_task_save_result(servicetask):
    t = Task(servicetask)
    t.result = Result()
    assert t.save_result() is None
    assert os.path.exists(f"/tmp/{t.sid}_{t.sha256}_result.json") is True
    assert json.loads(open(f"/tmp/{t.sid}_{t.sha256}_result.json", "r").read()) == {
        "classification": "TLP:C",
        "response": {
            "milestones": {"service_started": None, "service_completed": None},
            "service_version": None,
            "service_name": "blah",
            "service_tool_version": None,
            "supplementary": [],
            "extracted": [],
            "service_context": None,
            "service_debug_info": None,
        },
        "result": {"score": 0, "sections": []},
        "partial": False,
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "text/plain",
        "size": 0,
        "drop_file": False,
        "temp_submission_data": {},
    }

    os.remove(f"/tmp/{t.sid}_{t.sha256}_result.json")


def test_task_set_service_context(servicetask):
    t = Task(servicetask)
    assert t.set_service_context("blah") is None
    assert t.service_context == "blah"


def test_task_start(servicetask):
    t = Task(servicetask)
    _, path = tempfile.mkstemp()
    with open(path, "w") as f:
        f.write("test")
    t.add_extracted(path, "name", "description", classification="TLP:AMBER")
    t.add_supplementary(path, "name", "description")
    assert len(t.extracted) == 1
    assert len(t.supplementary) == 1

    assert t.start("TLP:C", "service_version", "service_tool_version") is None
    assert t.service_version == "service_version"
    assert t.service_tool_version == "service_tool_version"
    assert t.service_default_result_classification == "TLP:C"
    assert isinstance(t._service_started, str)
    assert len(t.extracted) == 0
    assert len(t.supplementary) == 0


def test_task_success(servicetask):
    t = Task(servicetask)
    t.result = Result()
    assert t.success() is None
    assert isinstance(t._service_completed, str)
    assert os.path.exists(f"/tmp/{t.sid}_{t.sha256}_result.json") is True
    os.remove(f"/tmp/{t.sid}_{t.sha256}_result.json")


def test_task_validate_file(servicetask):
    t = Task(servicetask)

    # File does not exist
    with pytest.raises(Exception):
        t.validate_file()

    # File does exist but sha256 is mismatched
    path = f"/tmp/{t.sha256}"
    with open(path, "w") as f:
        f.write("test")

    with pytest.raises(Exception):
        t.validate_file()

    os.remove(path)

    # File exists and sha256 is a match
    # Backwards compatibility check with service base
    if hasattr(t, "fileinfo"):
        t.fileinfo.sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    else:
        t.sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    path = f"/tmp/{t.sha256}"
    with open(path, "w") as f:
        f.write("test")

    assert t.validate_file() == path

    os.remove(path)


def test_task_working_directory(servicetask):
    t = Task(servicetask)
    assert t._working_directory is None
    # Initial call, _working_directory is None
    twd = t.working_directory
    assert os.path.exists(twd)
    assert os.path.isdir(twd)
    assert t._working_directory == twd

    # Subsequent call after _working_directory is set. values stay the same
    new_twd = t.working_directory
    assert new_twd == twd
