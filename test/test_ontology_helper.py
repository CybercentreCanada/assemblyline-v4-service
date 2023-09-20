from assemblyline_v4_service.common.ontology_helper import *

from assemblyline.odm.models.ontology.filetypes import PE


def test_ontologyhelper_init():
    oh = OntologyHelper(None, "blah")
    assert oh.log is None
    assert oh._file_info == {}
    assert oh._result_parts == {}
    assert oh.results == {}
    assert oh.service == "blah"


def test_ontologyhelper_add_file_part():
    oh = OntologyHelper(None, "blah")

    # Add None Model
    assert oh.add_file_part(None, None) is None
    assert oh._file_info == {}

    # Add PE Model with invalid data
    assert oh.add_file_part(PE, {"blah": "blah"}) is None
    assert isinstance(oh._file_info["pe"], PE)
    assert oh._file_info["pe"]["header"] is None

    # Add PE Model with valid data
    assert oh.add_file_part(PE, {"header": {"characteristics_hash": 123}}) is None
    assert isinstance(oh._file_info["pe"], PE)
    assert oh._file_info["pe"]["header"]["characteristics_hash"] == 123


# def test_
