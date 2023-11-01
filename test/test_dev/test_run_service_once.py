import os

from assemblyline_v4_service.dev.run_service_once import *

from assemblyline.common.identify import Identify


def test_runservice_init():
    rs = RunService()
    assert rs.service is None
    assert rs.service_class is None
    assert rs.submission_params is None
    assert rs.file_dir is None
    assert isinstance(rs.identify, Identify)


def test_runservice_try_run():
    # TODO
    pass


def test_runservice_stop():
    # TODO
    pass


def test_runservice_load_service_manifest():
    # TODO
    pass


def test_main():
    # TODO
    pass
