from assemblyline_v4_service.updater.helper import *


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
    # assert filter_downloads("output", "") == []
