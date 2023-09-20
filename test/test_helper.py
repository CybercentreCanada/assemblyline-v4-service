import pytest
from assemblyline_v4_service.common.helper import *

from assemblyline.common.classification import InvalidDefinition

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
    with pytest.raises(InvalidDefinition):
        get_classification()

    # TODO
    # The rest of the method


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
