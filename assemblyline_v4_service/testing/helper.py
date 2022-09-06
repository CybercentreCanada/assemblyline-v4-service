import errno
import json
import os
import pytest

from pathlib import Path

from assemblyline.common import forge
from assemblyline.common.dict_utils import flatten
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task
from cart import unpack_file


class TestHelper:
    def __init__(self, service_class, result_folder, extra_sample_locations=None):
        # Set service class to use
        self.service_class = service_class

        # Set location for samples
        self.locations = []

        # Extra samples location
        if extra_sample_locations:
            self.locations.append(extra_sample_locations)

        # Main samples location
        full_samples_location = os.environ.get("FULL_SAMPLES_LOCATION", None)
        if full_samples_location:
            self.locations.append(full_samples_location)

        # Set result folder location
        self.result_folder = result_folder

        # Load identify
        self.identify = forge.get_identify(use_cache=False)

        # Load submission params
        self.submission_params = helper.get_service_attributes().submission_params

    def _create_service_task(self, file_path, params):
        fileinfo_keys = ["magic", "md5", "mime", "sha1", "sha256", "size", "type"]

        # Set proper default values
        if params is None:
            params = {}

        metadata = params.get('metadata', {})
        temp_submission_data = params.get('temp_submission_data', {})
        submission_params = params.get('submission_params', {})
        tags = params.get('tags', [])

        return ServiceTask(
            {
                "sid": 1,
                "metadata": metadata,
                "deep_scan": False,
                "service_name": "Not Important",
                "service_config": {param.name: submission_params.get(param.name, param.default)
                                   for param in self.submission_params},
                "fileinfo": {k: v for k, v in self.identify.fileinfo(file_path).items() if k in fileinfo_keys},
                "filename": os.path.basename(file_path),
                "min_classification": "TLP:WHITE",
                "max_files": 501,
                "ttl": 3600,
                "temporary_submission_data": [
                    {'name': name, 'value': value} for name, value in temp_submission_data.items()
                ],
                "tags": tags,
            }
        )

    def _find_sample(self, sample):
        # Assume samples are carted
        sample = f"{sample}.cart"

        for location in self.locations:
            p = [path for path in Path(location).rglob(sample)]
            if len(p) == 1:
                return p[0]

        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), sample)

    @staticmethod
    def _generalize_result(result, temp_submission_data=None):
        # Create a result for this file that contain generalized information for testing and
        # detailed information as well so the service writter has a better idea of the impact
        # of its changes to the service output.
        generalized_results = {
            "files": {
                "extracted": sorted(
                    [{"name": x["name"], "sha256": x["sha256"]}
                     for x in result.get("response", {}).get("extracted", [])], key=lambda x: x["sha256"]
                ),
                "supplementary": sorted(
                    [{"name": x["name"], "sha256": x["sha256"]}
                     for x in result.get("response", {}).get("supplementary", [])], key=lambda x: x["sha256"]
                )
            },
            "results": {
                "heuristics": [],
                "tags": {},
                "temp_submission_data": temp_submission_data
            },
            "extra": {
                "sections": [],
                "score": result.get("result", {}).get('score', 0),
                "drop_file": result.get("drop", False)
            }
        }

        # Parse sections
        for section in result.get("result", {}).get("sections", []):

            # Add section to extras (This will not be tested)
            generalized_results['extra']['sections'].append(section)

            # Parse Heuristics
            heuristic = section.get('heuristic', None)
            sigs = []
            heur_id = None
            if heuristic:
                sigs = list(heuristic['signatures'].keys())
                heur_id = heuristic['heur_id']
                generalized_results["results"]["heuristics"].append(
                    {
                        "heur_id": heur_id,
                        "attack_ids": heuristic['attack_ids'],
                        'signatures': sigs
                    }
                )
            # Sort Heuristics
            generalized_results["results"]["heuristics"] = \
                sorted(generalized_results["results"]["heuristics"], key=lambda x: x["heur_id"])

            # Parse tags
            for k, v in flatten(section.get("tags", {})).items():
                generalized_results["results"]["tags"].setdefault(k, [])
                for tag in v:
                    generalized_results["results"]["tags"][k].append({
                        "value": tag,
                        "heur_id": heur_id,
                        "signatures": sigs
                    })
            # Sort Tags
            for k, v in generalized_results["results"]["tags"].items():
                generalized_results["results"]["tags"][k] = sorted(v, key=lambda x: x["value"])

        return generalized_results

    def _execute_sample(self, sample, save=False):
        file_path = os.path.join("/tmp", sample)
        cls = None

        try:
            # Find and unpack sample
            sample_path = self._find_sample(sample)
            unpack_file(sample_path, file_path)

            # Initialize service class
            cls = self.service_class()
            cls.start()

            # Load optional submission parameters
            params_file = os.path.join(self.result_folder, sample, 'params.json')
            if os.path.exists(params_file):
                params = json.load(open(params_file))
            else:
                params = {}

            # Create the service request
            task = Task(self._create_service_task(file_path, params))
            service_request = ServiceRequest(task)

            # Execute the service
            cls.execute(service_request)

            # Get results from the scan
            results = self._generalize_result(task.get_service_result(), task.temp_submission_data)

            # Save results if needs be
            if save:
                result_json = os.path.join(self.result_folder, sample, 'result.json')
                json.dump(results, open(result_json, 'w'), indent=2, allow_nan=False, sort_keys=True)

            return results
        finally:
            # Cleanup files
            if cls:
                cls._cleanup()
            if os.path.exists(file_path):
                os.remove(file_path)

    def result_list(self):
        return [f for f in os.listdir(self.result_folder)
                if len(f.split("_")[0]) == 64 and os.path.isdir(os.path.join(self.result_folder, f))]

    def compare_sample_results(self, sample):
        issues = []
        original_results_file = os.path.join(self.result_folder, sample, 'result.json')

        if os.path.exists(original_results_file):
            original_results = json.load(open(original_results_file))
            results = self._execute_sample(sample)

            # Pop off extra results
            original_results.pop('extra')
            results.pop('extra')

            # Compile the list of issues between the two results
            # Extracted files
            self._file_compare(
                issues, "Extracted", original_results['files']['extracted'],
                results['files']['extracted'])
            # Supplementary files
            self._file_compare(issues,
                               "Supplementary", original_results['files']['supplementary'],
                               results['files']['supplementary'])
            # Heuristics triggered
            self._heuristic_compare(issues, original_results['results']['heuristics'], results['results']['heuristics'])
            # Tags generated
            self._tag_compare(issues, original_results['results']['tags'], results['results']['tags'])
            # Temp submission data generated
            self._temp_data_compare(
                issues, original_results['results']['temp_submission_data'],
                results['results']['temp_submission_data'])
        else:
            issues.append(f"Original result file missing for sample: {sample}")

        return issues

    def run_test_comparison(self, sample):
        # WARNING: This function is only to be run into a pytest context!
        issues = self.compare_sample_results(sample)
        if len(issues) != 0:
            issues.insert(0, "")
            pytest.fail("\n".join(issues))

    @ staticmethod
    def _heuristic_compare(issues, original, new):
        oh_map = {x['heur_id']: x for x in original}
        nh_map = {x['heur_id']: x for x in new}
        for heur_id, heur in oh_map.items():
            if heur_id not in nh_map:
                issues.append(f"[HEUR] Heuristic #{heur_id} missing from results.")
            else:
                new_heur = nh_map[heur_id]
                for attack_id in heur['attack_ids']:
                    if attack_id not in new_heur['attack_ids']:
                        issues.append(f"[HEUR] Attack ID '{attack_id}' missing from heuristic #{heur_id}.")
                for signature in heur['signatures']:
                    if signature not in new_heur['signatures']:
                        issues.append(f"[HEUR] Signature '{signature}' missing from heuristic #{heur_id}.")

                for attack_id in new_heur['attack_ids']:
                    if attack_id not in heur['attack_ids']:
                        issues.append(f"[HEUR] Attack ID '{attack_id}' added to heuristic #{heur_id}.")
                for signature in new_heur['signatures']:
                    if signature not in heur['signatures']:
                        issues.append(f"[HEUR] Signature '{signature}' added to heuristic #{heur_id}.")

        for heur_id in nh_map.keys():
            if heur_id not in oh_map:
                issues.append(f"[HEUR] Heuristic #{heur_id} added to results.")

    @ staticmethod
    def _tag_compare(issues, original, new):
        for tag_type, tags in original.items():
            if tag_type not in new:
                issues.append(f"[TAG] Tag type '{tag_type}' missing from results.")
            else:
                otm = {x['value']: x for x in tags}
                ntm = {x['value']: x for x in new[tag_type]}
                for v, tag in otm.items():
                    if v not in ntm:
                        issues.append(f"[TAG] Tag '{v} [{tag_type}]' missing from the results.")
                    else:
                        new_tag = ntm[v]
                        if tag['heur_id'] != new_tag['heur_id']:
                            issues.append(f"[TAG] Heuristic ID for tag '{v} [{tag_type}]' has changed.")
                        if tag['signatures'] != new_tag['signatures']:
                            issues.append(f"[TAG] Associated signatures for tag '{v} [{tag_type}]' has changed.")

                for v in ntm.keys():
                    if v not in otm:
                        issues.append(f"[TAG] Tag '{v} [{tag_type}]' added to results.")

        for tag_type in new.keys():
            if tag_type not in original:
                issues.append(f"[TAG] Tag type '{tag_type}' added to results.")

    @ staticmethod
    def _temp_data_compare(issues, original, new):
        for k, v in original.items():
            if k not in new:
                issues.append(f"[TEMP_DATA] Temporary submission data with key '{k}' is missing from the results.")
            elif v != new[k]:
                issues.append(f"[TEMP_DATA] Value of temporary submission data with key '{k}' has changed.")

        for k, v in new.items():
            if k not in original:
                issues.append(f"[TEMP_DATA] Temporary submission data with key '{k}' was added to the results.")

    @ staticmethod
    def _file_compare(issues, f_type, original, new):
        oh_map = {x['sha256']: x['name'] for x in original}
        on_map = {x['name']: x['sha256'] for x in original}
        nh_map = {x['sha256']: x['name'] for x in new}
        nn_map = {x['name']: x['sha256'] for x in new}

        for sha256, name in oh_map.items():
            if sha256 not in nh_map:
                if name not in nn_map:
                    issues.append(f"[{f_type.upper()}] File '{name} [{sha256}]' missing from the file list.")
                    continue

                if sha256 != nn_map[name]:
                    issues.append(f"[{f_type.upper()}] The sha256 of the file '{name}' has changed.")
                    continue

            if name != nh_map[sha256]:
                issues.append(f"[{f_type.upper()}] The name of the file '{sha256}' has changed.")
                continue

        for sha256, name in nh_map.items():
            if sha256 not in oh_map and name not in on_map:
                issues.append(f"[{f_type.upper()}] File '{name} [{sha256}]' added to the file list.")

        return issues

    def regenerate_results(self):
        for f in self.result_list():
            try:
                self._execute_sample(f, save=True)
            except FileNotFoundError:
                print(f"[W] File {f} was not for in any of the following locations: {', '.join(self.locations)}")
