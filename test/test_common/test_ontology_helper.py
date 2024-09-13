import json
import logging
import os
import tempfile

from test.test_common import setup_module
setup_module()

import pytest
from assemblyline_v4_service.common.ontology_helper import OntologyHelper, validate_tags, merge_tags
from assemblyline_v4_service.common.result import ResultSection

from assemblyline.odm.models.ontology.ontology import ODM_VERSION
from assemblyline.odm.models.ontology.filetypes import PE
from assemblyline.odm.models.ontology.results import Antivirus


@pytest.fixture
def dummy_result_class_instance():
    class DummyResult:
        def __init__(self):
            self.sections = []

        def add_section(self, res_sec):
            self.sections.append(res_sec)
    return DummyResult()


@pytest.fixture
def dummy_task_class():
    class DummyTask:
        def __init__(self):
            self.supplementary = []
            self.extracted = []
            self.min_classification = None
            self.service_default_result_classification = None
            self.service_name = "blah"
            self.service_version = "4.0.0"
            self.service_tool_version = "blah"
    yield DummyTask


@pytest.fixture
def dummy_request_class(dummy_task_class, dummy_result_class_instance):
    class DummyRequest(dict):
        def __init__(self, **some_dict):
            super(DummyRequest, self).__init__()
            self.task = dummy_task_class()
            self.file_type = None
            self.sha256 = "blah"
            self.md5 = "blah"
            self.sha1 = "blah"
            self.file_size = 123
            self.file_name = "blah"
            self.deep_scan = False
            self.result = dummy_result_class_instance
            self.update(some_dict)

        def add_supplementary(self, path, name, description, classification):
            self.task.supplementary.append({"path": path, "name": name, "description": description, "classification": classification})

        def add_extracted(self, path, name, description):
            self.task.extracted.append({"path": path, "name": name, "description": description})

        def get_param(self, key):
            val = self.get(key, None)
            if val is None:
                raise Exception(f"Service submission parameter not found: {key}")
            else:
                return val

        @staticmethod
        def add_image(path, name, description, classification=None, ocr_heuristic_id=None, ocr_io=None):
            return {
                "img": {"path": path, "name": name, "description": description, "classification": classification},
                "thumb": {"path": path, "name": f"{name}.thumb", "description": description, "classification": classification}
            }

    yield DummyRequest


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


def test_add_result_part():
    log = logging.getLogger('assemblyline')

    oh = OntologyHelper(log, "blah")

    # Add PE Model with invalid data
    oid = "pe_2XPN27nQE41DCEGJbTHb5p"
    assert oh.add_result_part(PE, {"blah": "blah"}) == oid
    assert isinstance(oh._result_parts[oid], PE)

    # Add Antivirus Model with valid data
    oid_2 = "antivirus_7WVybQLECGWqS0DqePtVLp"
    assert oh.add_result_part(Antivirus, {"engine_name": "blah"}) == oid_2
    assert isinstance(oh._result_parts[oid_2], Antivirus)
    assert oh._result_parts[oid_2]["engine_name"] == "blah"
    assert oh._result_parts[oid_2]["objectid"]["tag"] == "blah"
    assert oh._result_parts[oid_2]["objectid"]["ontology_id"] == "antivirus_7WVybQLECGWqS0DqePtVLp"
    assert oh._result_parts[oid_2]["objectid"]["service_name"] == "blah"

def test_attach_parts():
    oh = OntologyHelper(None, "blah")

    # Default with empty values
    ont = {"file": {}, "results": {}}
    oh.attach_parts(ont)
    assert oh.results == {}
    assert ont["results"] == {}

    # Some values
    ont = {"file": {"blah": "blah"}, "results": {"blah": "blah"}}
    oh.attach_parts(ont)
    assert oh.results == {}
    assert ont["file"] == {"blah": "blah"}
    assert ont["results"] == {"blah": "blah"}

    # Some values, _file_info set
    oh._file_info = {"a": Antivirus({"objectid": {"tag": "a", "ontology_id": "b"}, "engine_name": "blah"})}
    ont = {"file": {"blah": "blah"}, "results": {"blah": "blah"}}
    oh.add_result_part(Antivirus, {"engine_name": "blah"})
    oh.add_other_part("test", "blah")
    oh.attach_parts(ont)
    assert oh.results == {
        'antivirus': [
            {
                'engine_name': 'blah',
                'objectid': {
                    'ontology_id': 'antivirus_7WVybQLECGWqS0DqePtVLp',
                    'service_name': 'blah',
                    'tag': 'blah'
                }
            }
        ]
    }
    assert ont["file"] == {
        "blah": "blah",
        "a": {
            "objectid": {
                "tag": "a", "ontology_id": "b", "service_name": "unknown"
            },
            "engine_name": "blah"
        }
    }
    assert ont["results"] == {
        'blah': 'blah',
        'antivirus': [
            {
                'objectid': {
                    'tag': 'blah',
                    'ontology_id': 'antivirus_7WVybQLECGWqS0DqePtVLp',
                    'service_name': 'blah'
                },
                'engine_name': 'blah'
            }
        ],
        'other': {
            'test': 'blah'
        }
    }


def test_attach_ontology(dummy_request_class):
    oh = OntologyHelper(None, "blah")
    req = dummy_request_class()
    working_dir = tempfile.mktemp()
    os.makedirs(working_dir, exist_ok=True)
    with open(os.path.join(working_dir, "blah.ontology"), "w") as f:
        f.write(json.dumps({"blah": "blah"}))

    # No result
    assert oh._attach_ontology(req, working_dir) is None

    # No tags
    req.result.sections = [ResultSection("blah")]
    assert oh._attach_ontology(req, working_dir) is None

    # With tags
    req.result.sections[0].add_tag("network.static.domain", "blah.com")
    assert oh._attach_ontology(req, working_dir) is None
    assert oh.results == {}
    assert req.task.supplementary == [
        {
            'classification': 'TLP:C',
            'description': 'Result Ontology from blah',
            'name': 'blah_blah.ontology',
            'path': os.path.join(working_dir, "blah.ontology")
        }
    ]

    with open(os.path.join(working_dir, "blah.ontology"), "r") as f:
        file_contents = json.loads(f.read())
    assert file_contents == {
        'classification': 'TLP:C',
        'file': {'md5': 'blah',
                'names': ['blah'],
                'sha1': 'blah',
                'sha256': 'blah',
                'size': 123,
                'type': None},
        'odm_type': 'Assemblyline Result Ontology',
        'odm_version': ODM_VERSION,
        'results': {'heuristics': [],
                    'tags': {'network.static.domain': ['blah.com']},
                    'score': 0},
        'service': {'name': 'blah',
                    'tool_version': 'blah',
                    'version': '4.0.0'}
    }

    # Assign a heuristic to the section and check to see if the score gets updated correctly
    req.result.sections[0].set_heuristic(1)
    req.result.sections.append(req.result.sections[0])
    req.task.supplementary = []
    assert oh._attach_ontology(req, working_dir) is None
    assert oh.results == {}
    assert req.task.supplementary == [
        {
            'classification': 'TLP:C',
            'description': 'Result Ontology from blah',
            'name': 'blah_blah.ontology',
            'path': os.path.join(working_dir, "blah.ontology")
        }
    ]

    with open(os.path.join(working_dir, "blah.ontology"), "r") as f:
        file_contents = json.loads(f.read())
    # The sum of the overall result should be 500 points since the heuristic was raised twice with a score of 250 per section
    assert file_contents == {
        'classification': 'TLP:C',
        'file': {'md5': 'blah',
                'names': ['blah'],
                'sha1': 'blah',
                'sha256': 'blah',
                'size': 123,
                'type': None},
        'odm_type': 'Assemblyline Result Ontology',
        'odm_version': ODM_VERSION,
        'results': {'heuristics': [{'tags': {'network.static.domain': ['blah.com']}, 'times_raised': 2, 'heur_id': 'BLAH_1', 'name': 'blah', 'score': 250}],
                    'tags': {'network.static.domain': ['blah.com']},
                    'score': 500},
        'service': {'name': 'blah',
                    'tool_version': 'blah',
                    'version': '4.0.0'}
    }


def test_validate_tags():
    # Valid tag
    assert validate_tags({'network.static.domain':['blah.com']})

    # Invalid tag
    assert not validate_tags({'blah':['blah.com']})

def test_merge_tags():
    # Merge with null should yield the tag map with value
    assert merge_tags({'abc':['xyz']}, None) == {'abc':['xyz']}
    assert merge_tags(None, {'abc':['xyz']}) == {'abc':['xyz']}

    # Merge with mutually exclusive keys
    assert merge_tags({'abc':['xyz']}, {'def':['xyz']}) == {
        'abc':['xyz'],
        'def':['xyz']
    }

    # Merge with non-mutually exclusive keys
    merged_tags = merge_tags({'abc':['xyz'], 'def':['tuv']}, {'def':['xyz']})
    merged_tags['def'] = sorted(merged_tags['def'])
    merged_tags == {
        'abc':['xyz'],
        'def':['tuv', 'xyz']
    }

def test_reset():
    oh = OntologyHelper(None, "blah")
    oh.reset()
    assert oh._file_info == {}
    assert oh._result_parts == {}
    assert oh.results == {}
