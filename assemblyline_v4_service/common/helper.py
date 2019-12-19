import os
import tempfile
from typing import Dict, Union

import yaml

from assemblyline.common.classification import Classification, InvalidDefinition
from assemblyline.common.dict_utils import recursive_update
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.service import Service


def get_classification() -> Classification:
    classification_yml = '/etc/assemblyline/classification.yml'

    classification_definition = {}

    '''default_file = os.path.join(os.path.dirname(__file__), 'classification.yml')
    if os.path.exists(default_file):
        with open(default_file) as default_fh:
            default_yml_data = yaml.safe_load(default_fh.read())
            if default_yml_data:
                classification_definition.update(default_yml_data)'''

    # while True:
        # Load modifiers from the yaml config
    if os.path.exists(classification_yml):
        with open(classification_yml) as yml_fh:
            yml_data = yaml.safe_load(yml_fh.read())
            if yml_data:
                classification_definition = recursive_update(classification_definition, yml_data)
                    # break
        # else:
        #     time.sleep(5)

    if not classification_definition:
        raise InvalidDefinition("Could not find any classification definition to load.")

    return Classification(classification_definition)


def get_heuristics() -> Dict[Union[str, int], Heuristic]:
    service_manifest_data = get_service_manifest()
    heuristics = service_manifest_data.get('heuristics', None)
    if heuristics:
        heuristics = {heuristic['heur_id']: Heuristic(heuristic) for heuristic in heuristics}
    return heuristics


def get_service_attributes() -> Service:
    service_manifest_data = get_service_manifest()

    # Pop the 'extra' data from the service manifest
    for x in ['file_required', 'tool_version', 'heuristics']:
        service_manifest_data.pop(x, None)

    try:
        service_attributes = Service(service_manifest_data)
    except ValueError as e:
        raise ValueError(f"Service manifest yaml contains invalid parameter(s): {str(e)}")

    return service_attributes


def get_service_manifest() -> Dict:
    service_manifest_yml = os.path.join(tempfile.gettempdir(), 'service_manifest.yml')
    if not os.path.exists(service_manifest_yml):
        service_manifest_yml = os.path.join(os.getcwd(), 'service_manifest.yml')

    if os.path.exists(service_manifest_yml):
        with open(service_manifest_yml) as yml_fh:
            yml_data = yaml.safe_load(yml_fh.read())
            if yml_data:
                return yml_data
            else:
                raise Exception("Service manifest is empty.")
    else:
        raise Exception("Service manifest YAML file not found in root folder of service.")
