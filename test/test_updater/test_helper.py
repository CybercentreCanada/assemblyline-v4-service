import os
import shutil
from logging import getLogger

import certifi
import pytest
import requests_mock
from assemblyline_v4_service.updater.helper import (
    SkipSource,
    add_cacert,
    filter_downloads,
    url_download,
)

HTML_FILE_REQUEST = "http://www.google.com/index.html"
ZIP_FILE_REQUEST = "http://www.google.com/index.zip"
TARGZ_FILE_REQUEST = "http://www.google.com/index.tar.gz"

INDEX = "/tmp/blah/index.html"
INDEX_ZIP = "/tmp/blah/index.zip"
INDEX_ZIP_TEXT = "/tmp/blah/index/test.txt"
INDEX_ZIP_EXTRACT_PATH = "/tmp/blah/index"
DIRECTORY = "/tmp/blah"
if os.getcwd().endswith("/test"):
    TAR = os.path.join(DIRECTORY, "blah.tar")
else:
    TAR = os.path.join(os.getcwd(), "blah.tar")


@pytest.fixture(autouse=True)
def setup_and_teardown_test():
    if os.path.exists(DIRECTORY):
        shutil.rmtree(DIRECTORY)

def test_add_cacert():
    fc = open(certifi.where(), "r").read()

    assert add_cacert("blah") is None
    with open(certifi.where(), "r") as f:
        assert f.read().endswith("\nblah")

    # Cleanup
    with open(certifi.where(), "w") as f:
        f.write(fc)


def test_filter_downloads():
    # No output_path
    assert filter_downloads("", "pattern") == []

    # No pattern

    os.makedirs(DIRECTORY, exist_ok=True)
    with open(INDEX, 'w') as f:
        f.write("test")

    # Output is a file

    assert filter_downloads(INDEX, "") == [(INDEX, '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')]

    # Pattern that hits
    assert filter_downloads(INDEX, ".*blah.*") == [(INDEX, '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')]

    # Pattern that misses
    assert filter_downloads(INDEX, ".*blahblah.*") == []

    # TODO
    # Output is a directory
    # output = filter_downloads(DIRECTORY, "")
    # assert output[0] == (INDEX, '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
    # # Note, the sha256 of the make_archive is unique every time, therefore we cannot test it consistently
    # assert output[1][0] == DIRECTORY + "/"
    # assert len(output) == 2


def test_url_download():
    log = getLogger()
    os.makedirs(DIRECTORY, exist_ok=True)

    # URI does not end with file name
    with pytest.raises(ValueError):
        url_download({"name": "blah", "uri": "http://google.com"}, 0, log, DIRECTORY)

    with requests_mock.Mocker() as m:
        # Expected
        m.head(HTML_FILE_REQUEST, text="blah")
        m.get(HTML_FILE_REQUEST, text="blah")
        m.post(HTML_FILE_REQUEST, text="blah")
        assert url_download({"name": "blah", "uri": HTML_FILE_REQUEST}, 0, log, DIRECTORY) == INDEX
        assert url_download({"name": "blah", "uri": HTML_FILE_REQUEST, "fetch_method": "get"}, 0, log, DIRECTORY) == INDEX
        assert url_download({"name": "blah", "uri": HTML_FILE_REQUEST, "fetch_method": "post",
                             "data": {"api-key": "123456"}}, 0, log, DIRECTORY) == INDEX

        os.remove(INDEX)

        # UNKNOWN FETCH METHOD
        with pytest.raises(ValueError, match="Unknown fetch method: test"):
            url_download({"name": "blah", "uri": HTML_FILE_REQUEST, "fetch_method": "test"}, 0, log, DIRECTORY)

        # NOT_MODIFIED
        m.get(HTML_FILE_REQUEST, status_code=304)
        with pytest.raises(SkipSource):
            url_download({"name": "blah", "uri": HTML_FILE_REQUEST}, 0, log, DIRECTORY)

        # NOT_FOUND
        m.get(HTML_FILE_REQUEST, status_code=404)
        assert url_download({"name": "blah", "uri": HTML_FILE_REQUEST}, 0, log, DIRECTORY) is None

@pytest.mark.parametrize("uri,filename",
                         argvalues=[(ZIP_FILE_REQUEST, "test.zip"),(TARGZ_FILE_REQUEST, "test.tar.gz")],
                         ids=["test.zip","test.tar.gz"])

def test_url_download_unpack(uri, filename):
    log = getLogger()
    os.makedirs(DIRECTORY, exist_ok=True)
    with requests_mock.Mocker() as m:
        m.head(uri, text="blah")
        fake_zip_path = os.path.join(os.path.dirname(__file__), filename)
        m.get(uri, content=open(fake_zip_path, "rb").read())
        assert url_download({"name": "index", "uri": uri}, 0, log, DIRECTORY) == INDEX_ZIP_EXTRACT_PATH


def test_git_clone_repo():
    # TODO
    pass
