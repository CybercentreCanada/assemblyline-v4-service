import json
import os
import tempfile

import pytest
import requests
import requests_mock
from assemblyline_v4_service.client import task_handler
from requests import ConnectionError, HTTPError, Session, Timeout, exceptions

from assemblyline.odm.models.service import Service

SERVICE_CONFIG_NAME = "service_manifest.yml"
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)


def setup_module():
    if not os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        open_manifest = open(TEMP_SERVICE_CONFIG_PATH, "w")
        open_manifest.write("\n".join([
            "name: Sample",
            "version: sample",
            "docker_config:",
            "    image: sample",
            "heuristics:",
            "  - heur_id: 17",
            "    name: blah",
            "    description: blah",
            "    filetype: '*'",
            "    score: 250",
        ]))
        open_manifest.close()


def teardown_module():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)

@pytest.fixture
def default_th():
    default_th = task_handler.TaskHandler()
    default_th.load_service_manifest()
    default_th.session = Session()
    return default_th



def test_path(default_th):
    # Default
    assert default_th._path("blah") == "http://localhost:5003/api/v1/blah/"

    # With args
    assert default_th._path("blah", "blah1", "blah2") == "http://localhost:5003/api/v1/blah/blah1/blah2/"


def test_load_service_manifest(default_th):
    service_object = Service(
        {
            "name": "Sample",
            "version": "sample",
            "docker_config": {
                "image": "sample"
            },
        }
    )
    assert default_th.service.__dict__ == service_object.__dict__


def test_update_service_manifest(default_th):
    default_th.update_service_manifest({"version": "pop me!", "other": "stuff"})
    assert default_th.service_manifest_data == {
        'name': 'Sample',
        'version': 'sample',
        'docker_config': {
            'image': 'sample'
        },
        'heuristics': [
            {
                'heur_id': 17,
                'name': 'blah',
                'description': 'blah',
                'filetype': '*',
                'score': 250
            }
        ],
        'other': 'stuff'
    }


def test_cleanup_working_directory(default_th):
    temp_dir = tempfile.mkdtemp()
    _, temp_abs_pathname = tempfile.mkstemp(dir=temp_dir)
    with open(temp_abs_pathname, "w") as f:
        f.write("TMP")
    nested_temp_dir = tempfile.mkdtemp(dir=temp_dir)

    default_th.cleanup_working_directory(temp_dir)
    assert not os.path.exists(temp_abs_pathname)
    assert not os.path.exists(nested_temp_dir)
    assert os.path.exists(temp_dir)

    # Test for task_fifo_path and done_fifo_path
    _, temp_fifo_abs_pathname = tempfile.mkstemp(dir=temp_dir)
    with open(temp_fifo_abs_pathname, "w") as f:
        f.write("TMP")
    default_th.task_fifo_path = temp_fifo_abs_pathname
    default_th.done_fifo_path = temp_fifo_abs_pathname
    default_th.cleanup_working_directory(temp_dir)

    # Check them all, even though they are all the same, just in case
    assert os.path.exists(temp_fifo_abs_pathname)
    assert os.path.exists(default_th.task_fifo_path)
    assert os.path.exists(default_th.done_fifo_path)

    assert os.path.exists(temp_dir)

    # Cleanup
    os.remove(temp_fifo_abs_pathname)
    os.removedirs(temp_dir)


def test_request_with_retries(default_th):
    url = "http://localhost"

    with requests_mock.Mocker() as m:
        # Normal get with no api response parsing, nothing fancy
        m.get(url)
        assert default_th.request_with_retries("get", url, get_api_response=False)

        # Some headers added
        assert default_th.request_with_retries("get", url, get_api_response=False, headers={"blah": "blah"})
        assert default_th.session.headers["blah"] == "blah"

        # Max retry set
        assert default_th.request_with_retries("get", url, get_api_response=False, max_retry=1)

        # Connection error with max retry of 1
        m.get(url, exc=ConnectionError)
        assert default_th.request_with_retries("get", url, get_api_response=False, max_retry=1) is None

        # Timeout error with max retry of 1
        m.get(url, exc=Timeout)
        assert default_th.request_with_retries("get", url, get_api_response=False, max_retry=1) is None

        # HTTPError error with max retry of 1
        m.get(url, exc=HTTPError)
        with pytest.raises(HTTPError):
            default_th.request_with_retries("get", url, get_api_response=False, max_retry=1) is None

        # exceptions.RequestException error with max retry of 1
        m.get(url, exc=exceptions.RequestException)
        with pytest.raises(exceptions.RequestException):
            default_th.request_with_retries("get", url, get_api_response=False, max_retry=1) is None

        # Api response parsing with no "api_response" key
        m.get(url, json={})
        with pytest.raises(KeyError):
            default_th.request_with_retries("get", url, get_api_response=True)

        # Api response parsing with "api_response" key
        m.get(url, json={"api_response": "blah"})
        assert default_th.request_with_retries("get", url, get_api_response=True) == "blah"

        # Api response parsing with status code of 400 and no "api_error_message" key
        m.get(url, json={}, status_code=400)
        with pytest.raises(HTTPError):
            default_th.request_with_retries("get", url, get_api_response=True)

        # Api response parsing with status code of 400 and "api_error_message" key
        m.get(url, json={"api_error_message": "blah"}, status_code=400)
        with pytest.raises(task_handler.ServiceServerException):
            default_th.request_with_retries("get", url, get_api_response=True)

        # Api response parsing with status code not 400
        m.get(url, json={"api_error_message": "blah"}, status_code=401)
        with pytest.raises(HTTPError):
            default_th.request_with_retries("get", url, get_api_response=True)


def test_try_run(default_th):
    default_th.headers = dict()

    _, default_th.task_fifo_path = tempfile.mkstemp()
    _, default_th.done_fifo_path = tempfile.mkstemp()

    with requests_mock.Mocker() as m:
        m.put(default_th._path('service', 'register'), json={"api_response": {"keep_alive": True, "new_heuristics": [], "service_config": {}}})
        default_th.register_only = False

        # Case where self.running is false
        default_th.running = False
        default_th.try_run()

        # Cases where self.running is True
        default_th.running = True

        # # Case where self.tasks_processed >= TASK_COMPLETE_LIMIT
        default_th.tasks_processed = 1
        task_handler.TASK_COMPLETE_LIMIT = 1
        default_th.try_run()

        m.get(default_th._path('task'), json={
            "api_response": {
                "task": {
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
            }
        })
        m.get(default_th._path('file', "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        m.post(default_th._path('task'), json={"api_response": {"success": True}})

        task_handler.TASK_COMPLETE_LIMIT = 2
        default_th.running = True
        with open(default_th.done_fifo_path, "w") as f:
            f.write(json.dumps(("/path/to/json", "blah")))
        default_th.try_run()
        assert default_th.status == "blah"
        assert default_th.task is None

        # Need to call this again since the service manifest gets deleted
        setup_module()


def test_connect_pipes(default_th):
    _, default_th.task_fifo_path = tempfile.mkstemp()
    _, default_th.done_fifo_path = tempfile.mkstemp()

    default_th.connect_pipes()
    assert default_th.task_fifo.mode == "w"
    assert os.path.exists(default_th.task_fifo_path)
    assert default_th.done_fifo.mode == "r"
    assert os.path.exists(default_th.done_fifo_path)


def test_initialize_service(default_th):
    _, default_th.task_fifo_path = tempfile.mkstemp()

    with requests_mock.Mocker() as m:
        # Do not keep alive
        m.put(default_th._path('service', 'register'), json={"api_response": {"keep_alive": False, "new_heuristics": []}})
        default_th.initialize_service()
        assert default_th.status == task_handler.STATUSES.STOPPING

        # Keep alive but register only
        m.put(default_th._path('service', 'register'), json={"api_response": {"keep_alive": True, "new_heuristics": []}})
        default_th.register_only = True
        default_th.initialize_service()
        assert default_th.status == task_handler.STATUSES.STOPPING

        # Keep alive / do not register only
        default_th.register_only = False
        m.put(default_th._path('service', 'register'), json={"api_response": {"keep_alive": True, "new_heuristics": [], "service_config": {"other": "different stuff"}}})
        default_th.initialize_service()

    assert default_th.service_manifest_data == {
        'name': 'Sample',
        'version': 'sample',
        'docker_config': {
            'image': 'sample'
        },
        'heuristics': [
            {
                'heur_id': 17,
                'name': 'blah',
                'description': 'blah',
                'filetype': '*',
                'score': 250
            }
        ],
        'other': 'different stuff'
    }

    assert default_th.status == task_handler.STATUSES.INITIALIZING


def test_get_task(default_th):
    with requests_mock.Mocker() as m:
        # No task
        m.get(default_th._path('task'), json={"api_response": {"task": False}})
        default_th.get_task()

        # Task received, but invalid. Should just see a log here.
        m.get(default_th._path('task'), json={"api_response": {"task": {"service_config": {}}}})
        default_th.get_task()

        # Task received, is valid.
        m.get(default_th._path('task'), json={
            "api_response": {
                "task": {
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
            }
        })
        task_as_prims = default_th.get_task().as_primitives()
        # Need to pop the sid because this is a randomly generated value
        task_as_prims.pop("sid")
        task_as_prims == {
            'deep_scan': False,
            'depth': 0,
            'fileinfo': {'magic': 'blah',
                         'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                         'mime': None,
                         'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                         'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                         'size': 0,
                         'type': 'text/plain'},
            'filename': 'blah',
            'ignore_cache': False,
            'ignore_recursion_prevention': False,
            'ignore_filtering': False,
            'max_files': 0,
            'metadata': {},
            'min_classification': 'TLP:C',
            'priority': 0,
            'safelist_config': {'enabled': False,
                                'enforce_safelist_service': False,
                                'hash_types': ['sha1',
                                               'sha256']},
            'service_config': {},
            'service_name': 'blah',
            # 'sid': '4bqSlBuxKuO6KdZrxYBqMC',
            'tags': [],
            'temporary_submission_data': [],
            'ttl': 0,
        }
        assert default_th.status == task_handler.STATUSES.WAITING_FOR_TASK


def test_download_file(default_th):
    default_th.headers = dict()

    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    sid = "4bqSlBuxKuO6KdZrxYBqMC"

    with requests_mock.Mocker() as m:
        # Content does not match given sha256
        m.get(default_th._path('file', sha256), text="blah")
        assert default_th.download_file(sha256, sid) is None
        assert default_th.status == task_handler.STATUSES.ERROR_FOUND

        # Content does match given sha256
        m.get(default_th._path('file', sha256))
        assert default_th.download_file(sha256, sid) == '/tmp/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        assert default_th.status == task_handler.STATUSES.DOWNLOADING_FILE_COMPLETED

        # Status code 404
        m.get(default_th._path('file', sha256), status_code=404)
        assert default_th.download_file(sha256, sid) is None
        assert default_th.status == task_handler.STATUSES.FILE_NOT_FOUND

        # Status code 500
        m.get(default_th._path('file', sha256), status_code=500, reason="cuz")
        assert default_th.download_file(sha256, sid) is None
        assert default_th.status == task_handler.STATUSES.ERROR_FOUND


def test_handle_task_result(default_th):
    default_th.headers = dict()

    _, result_json_path = tempfile.mkstemp()
    _, extracted_path = tempfile.mkstemp()
    with open(result_json_path, "w") as f:
        f.write(json.dumps({
            "response": {
                "extracted": [
                    {
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "classification": "blah",
                        "path": extracted_path,
                    }
                ],
                "supplementary": [],
                "service_tool_version": "123"
            }
        }))

    with requests_mock.Mocker() as m:
        m.get(default_th._path('task'), json={
            "api_response": {
                "task": {
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
            }
        })
        task = default_th.get_task()

        # It works!
        m.post(default_th._path('task'), json={"api_response": {"success": True}})
        assert default_th.handle_task_result(result_json_path, task) is None
        assert default_th.session.headers["Service-Tool-Version"] == "123"
        assert default_th.headers["Service-Tool-Version"] == "123"

        # It doesn't work (the first three times)
        callback_iteration = 0
        def json_callback(request, context):
            nonlocal callback_iteration
            if callback_iteration < 4:
                response = {"api_response": {"success": False, "missing_files": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]}}
            else:
                response = {"api_response": {"success": True}}
            callback_iteration += 1
            return response

        m.post(default_th._path('task'), json=json_callback)
        m.put(default_th._path('file'), json={"api_response": {}})

        assert default_th.handle_task_result(result_json_path, task) is None
        assert default_th.session.headers["Service-Tool-Version"] == "123"

        # ServiceServerException!
        m.post(default_th._path('task'), exc=task_handler.ServiceServerException)
        with pytest.raises(task_handler.ServiceServerException):
            default_th.handle_task_result(result_json_path, task)

        # requests.HTTPError
        m.post(default_th._path('task'), exc=requests.HTTPError)
        with pytest.raises(requests.HTTPError):
            default_th.handle_task_result(result_json_path, task)


def test_handle_task_error(default_th):
    with requests_mock.Mocker() as m:
        m.get(default_th._path('task'), json={
            "api_response": {
                "task": {
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
            }
        })
        task = default_th.get_task()

        m.post(default_th._path('task'), json={"api_response": {"success": True}})
        default_th.handle_task_error(task)


def test_stop(default_th):
    # WAITING_FOR_TASK
    default_th.status = task_handler.STATUSES.WAITING_FOR_TASK
    default_th.stop()
    assert default_th._shutdown_timeout == 90

    # ELSE
    default_th.status = "BLAH"
    default_th.stop()
    assert default_th._shutdown_timeout == 60

    # INITIALIZING
    default_th.status = task_handler.STATUSES.INITIALIZING
    default_th.stop()
    assert default_th._shutdown_timeout == 10

    # Open done_fifo and task_fifo
    default_th.done_fifo = open(tempfile.mkstemp()[0])
    default_th.task_fifo = open(tempfile.mkstemp()[0])
    default_th.stop()
