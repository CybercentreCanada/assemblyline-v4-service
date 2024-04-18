import json
import os

import pytest
from assemblyline_v4_service.updater.app import AUTH_KEY, NO_STATUS, STATUS_FILE, _get_status
from assemblyline_v4_service.updater.app import app as flask_app
from assemblyline_v4_service.updater.app import get_paths
from werkzeug.exceptions import ServiceUnavailable

DIRECTORY = "/tmp/blah"
TAR = "/tmp/blah/blah.tar"


@pytest.fixture(autouse=True)
def setup_and_teardown_test():
    if os.path.exists(TAR):
        os.remove(TAR)
    if os.path.exists(DIRECTORY):
        os.rmdir(DIRECTORY)
    if os.path.exists(STATUS_FILE):
        os.remove(STATUS_FILE)

    yield

    if os.path.exists(TAR):
        os.remove(TAR)
    if os.path.exists(DIRECTORY):
        os.rmdir(DIRECTORY)
    if os.path.exists(STATUS_FILE):
        os.remove(STATUS_FILE)


@pytest.fixture
def client():
    return flask_app.test_client()


def test_get_status():
    # NO_STATUS because STATUS_FILE does not exist
    assert _get_status() == NO_STATUS

    # STATUS_FILE exists
    with open(STATUS_FILE, "w") as f:
        f.write(json.dumps({
            'local_update_time': 1,
            'local_update_hash': "blah",
            'download_available': True,
            '_directory': DIRECTORY,
            '_tar': None,
        }))

    assert _get_status() == {'local_update_time': 1, 'local_update_hash': 'blah', 'download_available': True, '_directory': '/tmp/blah', '_tar': None}


def test_container_ready(client):
    response = client.get("/healthz/live")
    assert response.status_code == 200
    assert response.data == b"OK"
    assert response.json is None


def test_update_status(client):
    # No STATUS_FILE
    response = client.get("/status")
    assert response.status_code == 200
    assert response.json == {'_directory': None, '_tar': None, 'download_available': False, 'local_update_hash': None, 'local_update_time': 0}

    # STATUS_FILE exists
    with open(STATUS_FILE, "w") as f:
        f.write(json.dumps({
            'local_update_time': 1,
            'local_update_hash': "blah",
            'download_available': True,
            '_directory': DIRECTORY,
            '_tar': None,
        }))
    response = client.get("/status")
    assert response.status_code == 200
    assert response.json == {'_directory': DIRECTORY, '_tar': None, 'download_available': True, 'local_update_hash': 'blah', 'local_update_time': 1}


def test_api_login():
    # TODO
    pass


def test_get_paths():
    # No STATUS_FILE
    with pytest.raises(ServiceUnavailable):
        get_paths()

    # STATUS_FILE exists, but no path
    with open(STATUS_FILE, "w") as f:
        f.write(json.dumps({
            'local_update_time': 1,
            'local_update_hash': "blah",
            'download_available': True,
            '_directory': DIRECTORY,
            '_tar': TAR,
        }))

    with pytest.raises(ServiceUnavailable):
        get_paths()

    # Directory exists now, but still no tar file
    os.makedirs(DIRECTORY, exist_ok=True)
    with pytest.raises(ServiceUnavailable):
        get_paths()

    # TODO
    # Tar file exists now
    # with open(TAR, 'w') as f:
    #     f.write("test")

    # assert get_paths() == (DIRECTORY, TAR)


def test_list_files(client):
    # No STATUS_FILE
    response = client.get("/files", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 503

    # STATUS_FILE exists, but no path
    with open(STATUS_FILE, "w") as f:
        f.write(json.dumps({
            'local_update_time': 1,
            'local_update_hash': "blah",
            'download_available': True,
            '_directory': DIRECTORY,
            '_tar': TAR,
        }))

    response = client.get("/files", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 503

    # Directory exists now, but still no tar file
    os.makedirs(DIRECTORY, exist_ok=True)
    response = client.get("/files", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 503

    # Tar file exists now
    with open(TAR, 'w') as f:
        f.write("test")

    response = client.get("/files", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 200
    assert response.json == {'files': ['/tmp/blah/blah.tar']}


def test_get_file(client):
    # No STATUS_FILE
    response = client.get("/files/blah.tar", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 503

    # STATUS_FILE exists, but no path
    with open(STATUS_FILE, "w") as f:
        f.write(json.dumps({
            'local_update_time': 1,
            'local_update_hash': "blah",
            'download_available': True,
            '_directory': DIRECTORY,
            '_tar': TAR,
        }))

    response = client.get("/files/blah.tar", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 503

    # Directory exists now, but still no tar file
    os.makedirs(DIRECTORY, exist_ok=True)
    response = client.get("/files/blah.tar", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 503

    # Tar file exists now
    with open(TAR, 'w') as f:
        f.write("test")

    response = client.get("/files/blah.tar", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 200
    assert response.data == b"test"


def test_get_all_files(client):
    # No STATUS_FILE
    response = client.get("/tar", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 503

    # STATUS_FILE exists, but no path
    with open(STATUS_FILE, "w") as f:
        f.write(json.dumps({
            'local_update_time': 1,
            'local_update_hash': "blah",
            'download_available': True,
            '_directory': DIRECTORY,
            '_tar': TAR,
        }))

    response = client.get("/tar", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 503

    # Directory exists now, but still no tar file
    os.makedirs(DIRECTORY, exist_ok=True)
    response = client.get("/tar", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 503

    # Tar file exists now
    with open(TAR, 'w') as f:
        f.write("test")

    response = client.get("/tar", headers={"x-apikey": AUTH_KEY})
    assert response.status_code == 200
    assert response.data == b"test"
