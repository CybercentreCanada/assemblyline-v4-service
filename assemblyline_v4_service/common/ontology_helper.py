import json
import os
from collections import defaultdict
from typing import Any, Dict, Optional, List, Tuple

from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.result import HEUR_LIST, ResultSection

from assemblyline.common import forge
from assemblyline.common.dict_utils import flatten, get_dict_fingerprint_hash, unflatten
from assemblyline.odm.base import Model, construct_safe
from assemblyline.odm.models.ontology import ODM_VERSION
from assemblyline.odm.models.ontology.filetypes import PE
from assemblyline.odm.models.ontology.results import NetworkConnection
from assemblyline.odm.models.tagging import Tagging

ONTOLOGY_FILETYPE_MODELS = [PE]
ONTOLOGY_CLASS_TO_FIELD = {
    NetworkConnection: "netflow"
}

if not HEUR_LIST:
    # Get heuristics of service if not already set
    HEUR_LIST = helper.get_heuristics()

Classification = forge.get_classification()


# Cleanup invalid tagging from service results
def validate_tags(tag_map: Dict[str, List[str]]) -> Dict[str, List[str]]:
    tag_map, _ = construct_safe(Tagging, unflatten(tag_map))
    tag_map = flatten(tag_map.as_primitives(strip_null=True))
    return tag_map

# Merge tags
def merge_tags(tag_a: Dict[str, List[str]], tag_b: Dict[str, List[str]]) -> Dict[str, List[str]]:
    if not tag_a:
        return tag_b

    elif not tag_b:
        return tag_a

    all_keys = list(tag_a.keys()) + list(tag_b.keys())
    return {key: list(set(tag_a.get(key, []) + tag_b.get(key, []))) for key in all_keys}

class OntologyHelper:
    def __init__(self, logger, service_name) -> None:
        self.log = logger
        self._file_info = dict()
        self._result_parts: Dict[str, Model] = dict()
        self._other: Dict[str, str] = dict()
        self.results = defaultdict(list)
        self.service = service_name

    def add_file_part(self, model: Model, data: Dict) -> None:
        if not data:
            return None

        # Unlike result parts, there should only be one file part per type
        if model in ONTOLOGY_FILETYPE_MODELS:
            self._file_info[model.__name__.lower()] = model(data)

    def add_result_part(self, model: Model, data: Dict) -> str:
        if not data:
            self.log.warning(f'No data given to apply to model {model.__name__}')
            return None

        if not data.get('objectid'):
            data['objectid'] = {}

        oid = data['objectid'].get('ontology_id')
        tag = data['objectid'].get('tag')

        # Generate ID based on data and add reference to collection, prefix with model type
        # Some models have a deterministic way of generating IDs using the data given
        if not oid:
            oid = model.get_oid(data) if hasattr(model, 'get_oid') else \
                f"{model.__name__.lower()}_{get_dict_fingerprint_hash(data)}"
        if not tag:
            tag = model.get_tag(data) if hasattr(model, 'get_tag') else None

        data['objectid']['tag'] = tag
        data['objectid']['ontology_id'] = oid
        data['objectid']['service_name'] = self.service

        if not hasattr(model, "objectid"):
            data.pop("objectid")

        try:
            self._result_parts[oid] = model(data)
        except Exception as e:
            self.log.error(f'Problem applying data to given model: {e}')
            self.log.debug(data)
            oid = None
        finally:
            return oid

    def add_other_part(self, key: str, data: str) -> None:
        self._other[key] = data

    def attach_parts(self, ontology: Dict) -> None:
        ontology['file'].update({k: v.as_primitives(strip_null=True) for k, v in self._file_info.items()})

        # If result section wasn't explicitly defined by service writer, use what we know
        if not self.results:
            for v in self._result_parts.values():
                # Some Ontology classes map to certain fields in the ontology that don't share the same name
                field = ONTOLOGY_CLASS_TO_FIELD.get(v.__class__, v.__class__.__name__.lower())
                self.results[field].append(v.as_primitives(strip_null=True))

        ontology['results'].update(self.results)

        if self._other:
            ontology['results']['other'] = self._other

    def _preprocess_result_for_dump(self, sections: List[ResultSection], current_max: str,
                                    heur_tag_map: Dict[str, Dict[str, Any]], tag_map: Dict[str, List[str]], score: int) -> Tuple[str, Dict[str, Dict[str, Any]], Dict[str, List[str]], int]:
            for section in sections:
                # Determine max classification of the overall result
                current_max = Classification.max_classification(section.classification, current_max)

                # Append tags raised by the service, if any
                section_tags = validate_tags(section.tags)
                if section_tags:
                    tag_map = merge_tags(tag_map, section_tags)

                # Append tags associated to heuristics raised by the service, if any
                if section.heuristic:
                    heur = HEUR_LIST[section.heuristic.heur_id]
                    key = f'{self.service.upper()}_{heur.heur_id}'
                    heur_tag_map[key].update({
                        "heur_id": key,
                        "name": heur.name,
                        "tags": merge_tags(heur_tag_map[key]["tags"], section_tags) if section_tags else {},
                        "score": heur.score,
                        "times_raised": heur_tag_map[key]["times_raised"] + 1
                    })
                    score += section.heuristic.score

                # Recurse through subsections
                if section.subsections:
                    current_max, heur_tag_map, tag_map, score = self._preprocess_result_for_dump(
                        section.subsections, current_max, heur_tag_map, tag_map, score)

            return current_max, heur_tag_map, tag_map, score

    def _attach_ontology(self, request, working_dir) -> Optional[str]:
        if not request.result or not request.result.sections:
            # No service results, therefore no ontological output
            return

        max_result_classification, heur_tag_map, tag_map, score = self._preprocess_result_for_dump(
            sections=request.result.sections,
            current_max=Classification.max_classification(request.task.min_classification,
                                                          request.task.service_default_result_classification),
            heur_tag_map=defaultdict(lambda: {"tags": dict(), "times_raised": int()}),
            tag_map=defaultdict(list),
            score=0)

        if not heur_tag_map and not tag_map and not self._result_parts:
            # No heuristics, tagging, or ontologies found, therefore informational results
            return

        ontology = {
            'odm_type': 'Assemblyline Result Ontology',
            'odm_version': ODM_VERSION,
            "classification": max_result_classification,
            "file": {
                'md5': request.md5,
                'sha1': request.sha1,
                'sha256': request.sha256,
                'type': request.file_type,
                'size': request.file_size,
                'names': [request.file_name] if request.file_name else []
            },
            "service": {
                'name': request.task.service_name,
                'version': request.task.service_version,
                'tool_version': request.task.service_tool_version,
            },
            "results": {
                "tags": tag_map,
                "heuristics": list(heur_tag_map.values()),
                "score": score
            }
        }

        self.attach_parts(ontology)

        # Include Ontological data
        ontology_suffix = f"{request.sha256}.ontology"
        ontology_path = os.path.join(working_dir, ontology_suffix)
        with open(ontology_path, 'w') as f:
            f.write(json.dumps(ontology))
        attachment_name = f'{request.task.service_name}_{ontology_suffix}'.lower()
        request.add_supplementary(path=ontology_path, name=attachment_name,
                                  description=f"Result Ontology from {request.task.service_name}",
                                  classification=max_result_classification)

    def reset(self) -> None:
        self._file_info = {}
        self._result_parts = {}
        self.results = defaultdict(list)
