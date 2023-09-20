import pytest
from assemblyline_v4_service.common.helper import *

from assemblyline.common.classification import Classification

SERVICE_CONFIG_NAME = "service_manifest.yml"
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)


def setup_module():
    if not os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        open_manifest = open(TEMP_SERVICE_CONFIG_PATH, "w")
        open_manifest.write("\n".join([
            "name: Sample",
            "version: $SERVICE_TAG",
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
        open_manifest.close()


def teardown_module():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)


def test_get_classification():
    classification = get_classification()
    assert classification.__dict__ == {
        'original_definition': {
                'enforce': False, 'dynamic_groups': False
            },
            'levels_map': {
                'INV': 10001, '10001': 'INV', 'NULL': 0, '0': 'NULL'
            },
            'levels_map_stl': {
                'INV': 'INVALID', 'NULL': 'NULL'
            },
            'levels_map_lts': {
                'INVALID': 'INV', 'NULL': 'NULL'
            },
            'levels_styles_map': {},
            'levels_aliases': {},
            'access_req_map_lts': {},
            'access_req_map_stl': {},
            'access_req_aliases': {},
            'groups_map_lts': {},
            'groups_map_stl': {},
            'groups_aliases': {},
            'groups_auto_select': [],
            'groups_auto_select_short': [],
            'subgroups_map_lts': {},
            'subgroups_map_stl': {},
            'subgroups_aliases': {},
            'subgroups_auto_select': [],
            'subgroups_auto_select_short': [],
            'params_map': {},
            'description': {},
            'invalid_mode': True,
            '_classification_cache': set(),
            '_classification_cache_short': set(),
            'enforce': False,
            'dynamic_groups': False,
            'dynamic_groups_type': 'email',
            'UNRESTRICTED': 'NULL',
            'RESTRICTED': 'INVALID'
        }
    assert isinstance(classification, Classification)

    # TODO
    # Mock '/etc/assemblyline/classification.yml'


def test_get_heuristics():
    heuristics = get_heuristics()
    assert isinstance(heuristics[17], Heuristic)


def test_get_service_attributes():
    service_attributes = get_service_attributes()
    assert isinstance(service_attributes, Service)


def test_get_service_manifest():
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
        'version': '4.4.0.dev0',
    }

    # Stable
    with open(TEMP_SERVICE_CONFIG_PATH, "w") as f:
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
    os.remove(TEMP_SERVICE_CONFIG_PATH)
    with pytest.raises(Exception):
        get_service_manifest()

    # Empty service manifest
    with open(TEMP_SERVICE_CONFIG_PATH, "w") as f:
        pass
    with pytest.raises(Exception):
        get_service_manifest()
