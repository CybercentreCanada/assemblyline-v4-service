from assemblyline.common import forge
from assemblyline.common.dict_utils import flatten, unflatten, get_dict_fingerprint_hash
from assemblyline.odm.base import Model, construct_safe
from assemblyline.odm.models.ontology.filetypes import PE
from assemblyline.odm.models.ontology import ResultOntology
from assemblyline.odm.models.tagging import Tagging
from assemblyline_v4_service.common import helper

from collections import defaultdict
from typing import Dict

import json
import os

ONTOLOGY_FILETYPE_MODELS = [PE]


class OntologyHelper:
    def __init__(self, logger) -> None:
        self.log = logger
        self._file_info = dict()
        self._result_parts: Dict[str, Model] = dict()
        self.results = defaultdict(list)

    def add_file_part(self, model: Model, data: Dict) -> None:
        if not data:
            return None

        # Unlike result parts, there should only be one file part per type
        if model in ONTOLOGY_FILETYPE_MODELS:
            self._file_info[model.__name__.lower()] = model(data)

    def add_result_part(self, model: Model, data: Dict, parent=None) -> str:
        if not data:
            self.log.warning(f'No data given to apply to model {model.__name__}')
            return None

        # Generate ID based on data and add reference to collection, prefix with model type
        # Some models have a deterministic way of generating IDs using the data given
        oid = model.get_oid(data) if hasattr(model, 'get_oid') else \
            f"{model.__name__.lower()}_{get_dict_fingerprint_hash(data)}"
        data.update({'oid': oid})
        try:
            modeled_data = model(data)

            # If we have a parent, add references for a parent-child relationship
            parent_model = self._result_parts.get(parent)
            if parent_model:
                # Ensure parent was set on data
                modeled_data.oid_parent = parent
                parent_model.oid_children.append(oid)
                self._result_parts[parent] = parent_model
            self._result_parts[oid] = modeled_data
        except Exception as e:
            self.log.error(f'Problem applying data to given model: {e}')
            oid = None
        finally:
            return oid

    def attach_parts(self, ontology: Dict) -> None:
        ontology['file'].update({k: v.as_primitives() for k, v in self._file_info.items()})

        # If result section wasn't explicitly defined by service writer, use what we know
        if not self.results:
            [self.results[v.__class__.__name__.lower()].append(v.as_primitives()) for v in self._result_parts.values()]

        ontology['results'].update(self.results)

    def _attach_ontology(self, request, working_dir) -> str:
        # Get heuristics of service
        heuristics = helper.get_heuristics()

        def preprocess_result_for_dump(sections, current_max, heur_tag_map, tag_map):
            for section in sections:
                # Determine max classification of the overall result
                current_max = forge.get_classification().max_classification(section.classification, current_max)

                # Cleanup invalid tagging from service results
                def validate_tags(tag_map):
                    tag_map, _ = construct_safe(Tagging, unflatten(tag_map))
                    tag_map = flatten(tag_map.as_primitives(strip_null=True))
                    return tag_map

                # Merge tags
                def merge_tags(tag_a, tag_b):
                    if not tag_a:
                        return tag_b

                    elif not tag_b:
                        return tag_a

                    all_keys = list(tag_a.keys()) + list(tag_b.keys())
                    return {key: list(set(tag_a.get(key, []) + tag_b.get(key, []))) for key in all_keys}

                # Append tags raised by the service, if any
                section_tags = validate_tags(section.tags)
                if section_tags:
                    tag_map.update(section_tags)

                # Append tags associated to heuristics raised by the service, if any
                if section.heuristic:
                    heur = heuristics[section.heuristic.heur_id]
                    key = f'{request.task.service_name.upper()}_{heur.heur_id}'
                    heur_tag_map[key].update({
                        "heur_id": key,
                        "name": heur.name,
                        "tags": merge_tags(heur_tag_map[key]["tags"], section_tags) if section_tags else {},
                        "score": heur.score,
                        "times_raised": heur_tag_map[key]["times_raised"] + 1
                    })

                # Recurse through subsections
                if section.subsections:
                    current_max, heur_tag_map, tag_map = preprocess_result_for_dump(
                        section.subsections, current_max, heur_tag_map, tag_map)

            return current_max, heur_tag_map, tag_map

        if not request.result or not request.result.sections:
            # No service results, therefore no ontological output
            return

        max_result_classification, heur_tag_map, tag_map = preprocess_result_for_dump(
            request.result.sections, request.task.service_default_result_classification,
            defaultdict(lambda: {"tags": dict(), "times_raised": int()}),
            defaultdict(list))

        if not tag_map and not self._result_parts:
            # No tagging or ontologies found, therefore informational results
            return

        ontology = {
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
                "heuristics": list(heur_tag_map.values())
            }
        }

        self.attach_parts(ontology)

        # Include Ontological data
        ontology_suffix = f"{request.sha256}.ontology"
        ontology_path = os.path.join(working_dir, ontology_suffix)
        open(ontology_path, 'w').write(json.dumps(ResultOntology(ontology).as_primitives(strip_null=True)))
        attachment_name = f'{request.task.service_name}_{ontology_suffix}'.lower()
        request.add_supplementary(path=ontology_path, name=attachment_name,
                                  description=f"Result Ontology from {request.task.service_name}",
                                  classification=max_result_classification)

    def reset(self) -> None:
        self._file_info = {}
        self._result_parts = {}
        self.results = defaultdict(list)
