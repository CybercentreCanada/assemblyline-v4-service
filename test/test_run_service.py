import pytest
import os

from assemblyline.odm.messages.task import Task as ServiceTask
import assemblyline.common.importing

os.environ["SERVICE_PATH"] = "test"
from assemblyline_v4_service.run_service import RunService


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


def test_runservice_parse_task_message():
    rs = RunService(1)

    # TODO: Remove this scenario when we switch to rust service base
    task_message = "/fake/path/to/nothing.c"

    json_path, task_dir = rs._parse_task_message(task_message)

    assert json_path == task_message
    assert task_dir is None

    task_message = '["/task/dir", "/fake/path/"]'
    json_path, task_dir = rs._parse_task_message(task_message)

    assert json_path == "/fake/path/"
    assert task_dir == "/task/dir"


# TODO write test for run_service
