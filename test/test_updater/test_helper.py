import os
import time
from logging import getLogger
from tempfile import TemporaryDirectory

import certifi
import git
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
    # Set working directory to System.DefaultWorkingDirectory to ensure we have the right permissions for git operations
    working_dir = os.environ.get("System.DefaultWorkingDirectory")
    with TemporaryDirectory(dir=working_dir) as tmp_dir:
        # Missing 'uri' or 'name' should raise
        with pytest.raises(KeyError):
            git_clone_repo({}, logger=log, output_dir=tmp_dir)

        # Successful clone
        with TemporaryDirectory(dir=working_dir) as repo_dir:
            # Create a real git repo to clone from
            repo = git.Repo.init(repo_dir)
            test_file = os.path.join(repo_dir, "test.txt")
            with open(test_file, "w") as f:
                f.write("hello")
            repo.index.add(["test.txt"])
            repo.index.commit("initial commit")

            source = {"name": "test_repo", "uri": repo_dir}
            result = git_clone_repo(source, logger=log, output_dir=tmp_dir)
            assert result == os.path.join(tmp_dir, "test_repo")
            assert os.path.isdir(result)
            assert os.path.isfile(os.path.join(result, "test.txt"))

        # Clone with branch
        with TemporaryDirectory(dir=working_dir) as repo_dir:
            repo = git.Repo.init(repo_dir)
            test_file = os.path.join(repo_dir, "test.txt")
            with open(test_file, "w") as f:
                f.write("main")
            repo.index.add(["test.txt"])
            repo.index.commit("main commit")
            repo.create_head("dev")
            repo.heads.dev.checkout()
            with open(test_file, "w") as f:
                f.write("dev")
            repo.index.add(["test.txt"])
            repo.index.commit("dev commit")
            repo.heads.master.checkout()

            source = {"name": "test_repo", "uri": repo_dir, "git_branch": "dev"}
            result = git_clone_repo(source, logger=log, output_dir=tmp_dir)
            with open(os.path.join(result, "test.txt")) as f:
                assert f.read() == "dev"

        # SkipSource when previous_update is newer than last commit
        with TemporaryDirectory(dir=working_dir) as repo_dir:
            repo = git.Repo.init(repo_dir)
            test_file = os.path.join(repo_dir, "test.txt")
            with open(test_file, "w") as f:
                f.write("hello")
            repo.index.add(["test.txt"])
            repo.index.commit("initial commit")

            source = {"name": "test_repo", "uri": repo_dir}
            # Use a future timestamp so the commit is older than previous_update
            future_ts = int(time.time()) + 100000
            with pytest.raises(SkipSource):
                git_clone_repo(source, previous_update=future_ts, logger=log, output_dir=tmp_dir)

        # No SkipSource when previous_update is older than last commit
        with TemporaryDirectory(dir=working_dir) as repo_dir:
            repo = git.Repo.init(repo_dir)
            test_file = os.path.join(repo_dir, "test.txt")
            with open(test_file, "w") as f:
                f.write("hello")
            repo.index.add(["test.txt"])
            repo.index.commit("initial commit")

            source = {"name": "test_repo", "uri": repo_dir}
            result = git_clone_repo(source, previous_update=0, logger=log, output_dir=tmp_dir)
            assert result == os.path.join(tmp_dir, "test_repo")

        # Even if the commit is one second newer than the last update, it should not skip
        with TemporaryDirectory(dir=working_dir) as repo_dir:
            repo = git.Repo.init(repo_dir)
            test_file = os.path.join(repo_dir, "test.txt")
            with open(test_file, "w") as f:
                f.write("hello")
            repo.index.add(["test.txt"])
            repo.index.commit("initial commit")

            source = {"name": "test_repo", "uri": repo_dir}

            previous_update = next(repo.iter_commits()).committed_date - 1
            result = git_clone_repo(source, previous_update=previous_update, logger=log, output_dir=tmp_dir)
            assert result == os.path.join(tmp_dir, "test_repo")
