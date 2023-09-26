from test import setup_module, teardown_module

import pytest
from assemblyline_v4_service.common.helper import *

from assemblyline.common.classification import InvalidDefinition


def test_get_classification():
    with pytest.raises(InvalidDefinition):
        get_classification()

    # TODO
    # The rest of the method


def test_get_heuristics():
    heuristics = get_heuristics()
    assert isinstance(heuristics[1], Heuristic)


def test_get_service_attributes():
    service_attributes = get_service_attributes()
    assert isinstance(service_attributes, Service)


def test_get_service_manifest():
    service_manifest = get_service_manifest()
    assert service_manifest == {
        'config': {'ocr': {'banned': ['donotscanme'], 'macros': [], 'ransomware': []}},
        'docker_config': {'image': 'sample'},
        'heuristics': [{'attack_id': 'T1005',
                        'description': 'blah',
                        'filetype': '*',
                        'heur_id': 1,
                        'name': 'blah',
                        'score': 250,
                        'max_score': 1200}],
        'name': 'Sample',
        'version': '4.4.0.dev0',
    }

    teardown_module()
    # Stable
    with open("/tmp/service_manifest.yml", "w") as f:
        f.write("\n".join([
            "name: Sample",
            "version: 4.4.0.stable123",
            "docker_config:",
            "    image: sample",
            "heuristics:",
            "  - heur_id: 17",
            "    name: blah",
            "    description: blah",
            "    filetype: '*'",
            "    score: 250",
            "    attack_id: T123",
        ]))
    service_manifest = get_service_manifest()
    assert service_manifest == {
        'docker_config': {'image': 'sample'},
        'heuristics': [{'attack_id': 'T123',
                        'description': 'blah',
                        'filetype': '*',
                        'heur_id': 17,
                        'name': 'blah',
                        'score': 250}],
        'name': 'Sample',
        'version': '4.4.0.123',
    }

    # No service manifest
    teardown_module()
    with pytest.raises(Exception):
        get_service_manifest()

    # Empty service manifest
    with open("/tmp/service_manifest.yml", "w") as f:
        pass
    with pytest.raises(Exception):
        get_service_manifest()

    teardown_module()
    setup_module()
