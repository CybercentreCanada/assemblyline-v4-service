import os
import time
from logging import getLogger
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import certifi
import pytest
import requests_mock
from assemblyline_v4_service.updater.helper import (
    SkipSource,
    add_cacert,
    filter_downloads,
    git_clone_repo,
    url_download,
)

FILE_REQUEST_TEMPLATE = "http://www.google.com/{file}"

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
    with TemporaryDirectory() as tmp_dir:
        index = os.path.join(tmp_dir, "index.html")
        with open(index, 'w') as f:
            f.write("test")

        # Output is a file

        assert filter_downloads(index, "") == [(index, '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')]

        # Pattern that hits
        assert filter_downloads(index, f".*{os.path.basename(tmp_dir)}.*") == [(index, '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')]

        # Pattern that misses
        assert filter_downloads(index, ".*blahblah.*") == []

    # TODO
    # Output is a directory
    # output = filter_downloads(DIRECTORY, "")
    # assert output[0] == (INDEX, '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
    # # Note, the sha256 of the make_archive is unique every time, therefore we cannot test it consistently
    # assert output[1][0] == DIRECTORY + "/"
    # assert len(output) == 2


def test_url_download():
    log = getLogger()
    with TemporaryDirectory() as tmp_dir:
        index = os.path.join(tmp_dir, "index.html")

        html_file_request = FILE_REQUEST_TEMPLATE.format(file="index.html")
        # URI does not end with file name
        with pytest.raises(ValueError):
            url_download({"name": "blah", "uri": "http://google.com"}, 0, log, tmp_dir)

        with requests_mock.Mocker() as m:
            # Expected
            m.head(html_file_request, text="blah")
            m.get(html_file_request, text="blah")
            m.post(html_file_request, text="blah")
            assert url_download({"name": "blah", "uri": html_file_request}, 0, log, tmp_dir) == index
            assert url_download({"name": "blah", "uri": html_file_request, "fetch_method": "get"}, 0, log, tmp_dir) == index
            assert url_download({"name": "blah", "uri": html_file_request, "fetch_method": "post",
                                "data": {"api-key": "123456"}}, 0, log, tmp_dir) == index

            os.remove(index)

            # UNKNOWN FETCH METHOD
            with pytest.raises(ValueError, match="Unknown fetch method: test"):
                url_download({"name": "blah", "uri": html_file_request, "fetch_method": "test"}, 0, log, tmp_dir)

            # NOT_MODIFIED
            m.get(html_file_request, status_code=304)
            with pytest.raises(SkipSource):
                url_download({"name": "blah", "uri": html_file_request}, 0, log, tmp_dir)

            # NOT_FOUND
            m.get(html_file_request, status_code=404)
            assert url_download({"name": "blah", "uri": html_file_request}, 0, log, tmp_dir) is None

@pytest.mark.parametrize("filename",
                         argvalues=["test.zip","test.tar.gz"],
                         ids=["test.zip","test.tar.gz"])

def test_url_download_unpack(filename):
    log = getLogger()
    with TemporaryDirectory() as tmp_dir:
        uri = FILE_REQUEST_TEMPLATE.format(file=filename)
        with requests_mock.Mocker() as m:
            m.head(uri, text="blah")
            fake_zip_path = os.path.join(os.path.dirname(__file__), filename)
            m.get(uri, content=open(fake_zip_path, "rb").read())
            assert url_download({"name": "index", "uri": uri}, 0, log, tmp_dir) == os.path.join(tmp_dir, "index")


def test_git_clone_repo():
    log = getLogger()
    with TemporaryDirectory() as tmp_dir:
        # Missing 'uri' or 'name' should raise
        with pytest.raises(KeyError):
            git_clone_repo({}, logger=log, output_dir=tmp_dir)

        def _make_mock_repo(committed_date):
            mock_repo = MagicMock()
            mock_commit = MagicMock()
            mock_commit.committed_date = committed_date
            mock_repo.iter_commits.return_value = iter([mock_commit])
            return mock_repo

        # Successful clone
        with patch("assemblyline_v4_service.updater.helper.Repo.clone_from") as mock_clone:
            mock_clone.return_value = _make_mock_repo(int(time.time()))
            source = {"name": "test_repo", "uri": "http://example.com/repo.git"}
            result = git_clone_repo(source, logger=log, output_dir=tmp_dir)
            assert result == os.path.join(tmp_dir, "test_repo")
            mock_clone.assert_called_once()
            call_kwargs = mock_clone.call_args
            assert call_kwargs[0][0] == "http://example.com/repo.git"
            assert call_kwargs[0][1] == os.path.join(tmp_dir, "test_repo")

            # Clone with branch
            mock_clone.return_value = _make_mock_repo(int(time.time()))
            source = {"name": "test_repo", "uri": "http://example.com/repo.git", "git_branch": "dev"}
            result = git_clone_repo(source, logger=log, output_dir=tmp_dir)
            call_kwargs = mock_clone.call_args
            assert call_kwargs[1]["branch"] == "dev"

            # SkipSource when previous_update is newer than last commit
            old_commit_time = 1000
            mock_clone.return_value = _make_mock_repo(old_commit_time)
            source = {"name": "test_repo", "uri": "http://example.com/repo.git"}
            future_ts = int(time.time()) + 100000
            with pytest.raises(SkipSource):
                git_clone_repo(source, previous_update=future_ts, logger=log, output_dir=tmp_dir)

            # No SkipSource when previous_update is older than last commit
            recent_commit_time = int(time.time())
            mock_clone.return_value = _make_mock_repo(recent_commit_time)
            source = {"name": "test_repo", "uri": "http://example.com/repo.git"}
            result = git_clone_repo(source, previous_update=0, logger=log, output_dir=tmp_dir)
            assert result == os.path.join(tmp_dir, "test_repo")

            # Even if the commit is one second newer than the last update, it should not skip
            commit_time = 5000
            mock_clone.return_value = _make_mock_repo(commit_time)
            source = {"name": "test_repo", "uri": "http://example.com/repo.git"}
            result = git_clone_repo(source, previous_update=commit_time - 1, logger=log, output_dir=tmp_dir)
            assert result == os.path.join(tmp_dir, "test_repo")
