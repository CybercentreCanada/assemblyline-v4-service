import json
import os
import time
from logging import Logger

import pytest
import requests_mock
from assemblyline_v4_service.common.base import *
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from assemblyline_v4_service.common.result import Result
from assemblyline_v4_service.common.task import Task

from assemblyline.common import exceptions
from assemblyline.common.version import FRAMEWORK_VERSION, SYSTEM_VERSION
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.service import Service


@pytest.fixture
def dummy_tar_class():
    class DummyTar:
        def __init__(self, members=[]):
            self.supplementary = None
            self.members = members

        def getnames(self):
            return [
                "reports/report.json",
                "hollowshunter/hh_process_123_dump_report.json",
                "hollowshunter/hh_process_123_scan_report.json",
                "hollowshunter/hh_process_123_blah.exe",
                "hollowshunter/hh_process_123_blah.shc",
                "hollowshunter/hh_process_123_blah.dll",
                "shots/0005.jpg",
                "shots/0010.jpg",
                "shots/0001_small.jpg",
                "shots/0001.jpg",
                "buffer/blahblah",
                "supplementary/blahblah",
                "network/blahblah",
            ]

        def extract(self, output, path=None):
            pass

        def extractall(elf, path=".", members=None, *, numeric_owner=False):
            pass

        def getmembers(self):
            return self.members

        def close(self):
            pass
    yield DummyTar


@pytest.fixture
def dummy_tar_member_class():
    class DummyTarMember:
        def __init__(self, name, size):
            self.name = name
            self.size = size

        def isfile(self):
            return True

        def startswith(self, val):
            return val in self.name
    yield DummyTarMember


def test_is_recoverable_runtime_error():
    assert is_recoverable_runtime_error("blah") is False
    assert is_recoverable_runtime_error("cannot schedule new futures after interpreter shutdown") is True
    assert is_recoverable_runtime_error("can't register atexit after shutdown") is True
    assert is_recoverable_runtime_error("cannot schedule new futures after shutdown") is True


def test_servicebase_init():
    # No config
    sb = ServiceBase()
    assert isinstance(sb.service_attributes, Service)
    assert sb.config == {
        'ocr': {'banned': ['donotscanme'], 'macros': [], 'ransomware': []},
        'submission_params': [{'default': 'blah', 'value': 'blah', 'name': 'thing', 'type': 'str'}]
    }
    assert sb.name == "sample"
    assert isinstance(sb.log, Logger)
    assert sb._task is None
    assert sb._working_directory is None
    assert sb._api_interface == None
    assert sb.dependencies == {}
    assert isinstance(sb.ontology, OntologyHelper)
    assert sb.rules_directory is None
    assert sb.rules_list == []
    assert sb.update_time is None
    assert sb.update_hash is None
    assert sb.update_check_time == 0.0
    assert sb.rules_hash is None
    assert sb.signatures_meta == {}

    # With config
    sb = ServiceBase({"blah": "blah"})
    assert sb.config == {
        'ocr': {'banned': ['donotscanme'], 'macros': [], 'ransomware': []},
        'submission_params': [{'default': 'blah', 'value': 'blah', 'name': 'thing', 'type': 'str'}],
        'blah': 'blah'
    }


def test_servicebase_get_dependencies_info():
    sb = ServiceBase()
    assert sb._get_dependencies_info() == {}

    # TODO
    # Add environment variable that ends with _key


def test_servicebase_cleanup():
    sb = ServiceBase()
    sb._task = "blah"
    sb._working_directory = "blah"
    sb.dependencies = {"updates": {}}
    sb._cleanup()
    assert sb._task is None
    assert sb._working_directory is None


def test_servicebase_handle_execute_failure():
    sb = ServiceBase()
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
    # Exception is not a RecoverableError
    sb._task = Task(st)
    assert sb._handle_execute_failure("blah", "blah") is None
    assert sb._task.extracted == []
    assert sb._task.supplementary == []
    assert sb._task.error_message == "blah"
    assert sb._task.error_status == "FAIL_NONRECOVERABLE"

    # Exception is a RecoverableError
    sb._task = Task(st)
    recov = exceptions.RecoverableError("blah")
    assert sb._handle_execute_failure(recov, "blah") is None
    assert sb._task.extracted == []
    assert sb._task.supplementary == []
    assert sb._task.error_message == "blah"
    assert sb._task.error_status == "FAIL_RECOVERABLE"


def test_servicebase_success():
    sb = ServiceBase()
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
    sb._task = Task(st)
    sb._task.result = Result()
    assert sb._success() is None
    assert isinstance(sb._task._service_completed, str)


def test_servicebase_warning():
    sb = ServiceBase()
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
    sb._task = Task(st)
    assert sb._warning("blah") is None


def test_servicebase_error():
    sb = ServiceBase()
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
    sb._task = Task(st)
    assert sb._error("blah") is None


def test_servicebase_get_api_interface():
    sb = ServiceBase()
    assert isinstance(sb.get_api_interface(), ServiceAPI)


def test_servicebase_execute():
    sb = ServiceBase()
    with pytest.raises(NotImplementedError):
        sb.execute("blah")


def test_servicebase_get_service_version():
    sb = ServiceBase()
    assert sb.get_service_version() == f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.0.dev0"


def test_servicebase_get_tool_version():
    sb = ServiceBase()
    # No rules_hash
    assert sb.get_tool_version() is None

    # rules_hash
    sb.rules_hash = "blah"
    assert sb.get_tool_version() == "blah"


def test_servicebase_handle_task():
    sb = ServiceBase()
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
    assert sb.handle_task(st) is None
    assert sb._task is None
    assert sb.ontology._file_info == {}
    assert sb.ontology._result_parts == {}
    assert sb.ontology.results == {}
    assert sb._working_directory is None


def test_servicebase_start():
    sb = ServiceBase()
    assert sb.start() is None


def test_servicebase_start_service():
    sb = ServiceBase()
    sb.dependencies["updates"] = {"host": "blah.com", "port": 123, "key": "blah"}

    # Mocking this method
    def _download_rules():
        pass
    sb._download_rules = _download_rules

    assert sb.start_service() is None

    # TODO
    # Mock UPDATES_DIR manipulation


def test_servicebase_stop():
    sb = ServiceBase()
    assert sb.stop() is None


def test_servicebase_stop_service():
    sb = ServiceBase()
    assert sb.stop_service() is None


def test_servicebase_working_directory():
    sb = ServiceBase()

    # _working_directory does not exist
    assert sb._working_directory is None
    sb.working_directory
    assert sb._working_directory is not None and os.path.exists(sb._working_directory)

    # _working_directory does exist
    assert sb.working_directory == sb._working_directory

    # _task exists
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
    sb._task = Task(st)
    sb._working_directory = None
    sb.working_directory
    assert sb._working_directory is not None and os.path.exists(sb._working_directory)
    assert sb._working_directory == sb._task.working_directory


def test_servicebase_download_rules(mocker, dummy_tar_class):
    sb = ServiceBase()
    # Fast exit
    sb.update_check_time = time.time()
    assert sb._download_rules() is None

    # Dependencies
    sb.update_check_time = time.time() - 30
    sb.dependencies["updates"] = {"host": "blah.com", "port": 123, "key": "blah"}
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("tempfile.mkdtemp", return_value=os.path.join(UPDATES_DIR, "blah"))
    mocker.patch("tarfile.open", return_value=dummy_tar_class())

    # Mocking this
    def _load_rules():
        pass
    sb._load_rules = _load_rules

    with requests_mock.Mocker() as m:
        m.get("https://blah.com:123/status", status_code=200,
              json={"download_available": "blah", "local_update_time": "blah", "local_update_hash": "blah"})
        m.get("https://blah.com:123/tar", status_code=200, json={"download_available": "blah"})
        assert sb._download_rules() is None
        assert sb.update_time == "blah"
        assert sb.update_hash == "blah"
        assert sb.rules_directory == "/updates/blah"
        assert sb.rules_hash == "e3b0c44"

        # Throw exception at tar phase
        sb = ServiceBase()
        sb.update_check_time = time.time() - 30
        sb.dependencies["updates"] = {"host": "blah.com", "port": 123, "key": "blah"}
        sb._load_rules = _load_rules

        m.get("https://blah.com:123/tar", exc=Exception("blah"))
        assert sb._download_rules() is None
        assert sb.update_time is None
        assert sb.update_hash is None
        assert sb.rules_directory == "/updates/blah"
        assert sb.rules_hash is None
        assert sb.rules_list == []


def test_servicebase_gen_rules_hash():
    sb = ServiceBase()
    sb.rules_directory = "/tmp/blah"
    os.mkdir(sb.rules_directory)

    # One signature
    with open(os.path.join(sb.rules_directory, "blah.txt"), "w") as f:
        f.write("this is a rule")
    with open(os.path.join(sb.rules_directory, SIGNATURES_META_FILENAME), "w") as f:
        f.write(json.dumps({"meta": "this is a signature meta file"}))
    assert sb._gen_rules_hash() == "22a4f5b"

    # Two signatures
    with open(os.path.join(sb.rules_directory, "blahblah.txt"), "w") as f:
        f.write("this is also a rule")
    assert sb._gen_rules_hash() == "22c1e85"

    os.remove(os.path.join(sb.rules_directory, SIGNATURES_META_FILENAME))
    os.remove(os.path.join(sb.rules_directory, "blah.txt"))
    os.remove(os.path.join(sb.rules_directory, "blahblah.txt"))
    os.rmdir(sb.rules_directory)


def test_servicebase_clear_rules():
    sb = ServiceBase()
    assert sb._clear_rules() is None


def test_servicebase_load_rules():
    sb = ServiceBase()
    with pytest.raises(NotImplementedError):
        sb._load_rules()
