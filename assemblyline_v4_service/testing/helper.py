import json
import os
import pytest
import shutil

from pathlib import Path

from assemblyline.common import forge
from assemblyline.common.dict_utils import flatten
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task
from cart import unpack_file


class FileMissing(Exception):
    pass


class IssueHelper:
    ACTION_MISSING = "--"
    ACTION_ADDED = "++"
    ACTION_CHANGED = "-+"

    TYPE_HEUR = "HEURISTICS"
    TYPE_TAGS = "TAGS"
    TYPE_TEMP = "TEMP_DATA"
    TYPE_SUPPLEMENTARY = "SUPPLEMENTARY"
    TYPE_EXTRACTED = "EXTRACTED"
    TYPE_EXTRA = "EXTRA"

    def __init__(self):
        self.issues = {}

    def add_issue(self, itype: str, action: str, message: str):
        self.issues.setdefault(itype, [])
        self.issues[itype].append((action, message))

    def get_issue_list(self):
        return [f"[{k.upper()}] {action.capitalize()} {message}"
                for k, v in self.issues.items()
                for action, message in v]

    def get_issues(self):
        return self.issues

    def has_issues(self):
        return len(self.issues.keys()) != 0


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
                "sid": get_random_id(),
                "metadata": metadata,
                "deep_scan": False,
                "service_name": self.service_class.__name__,
                "service_config": {param.name: submission_params.get(param.name, param.default)
                                   for param in self.submission_params},
                "fileinfo": {k: v for k, v in self.identify.fileinfo(file_path).items() if k in fileinfo_keys},
                "filename": os.path.basename(file_path),
                "min_classification": "TLP:W",
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
        sample = f"{sample.split('_', 1)[0]}.cart"

        for location in self.locations:
            p = [path for path in Path(location).rglob(sample)]
            if len(p) == 1:
                return p[0]

        raise FileMissing(sample)

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
                try:
                    generalized_results["results"]["tags"][k] = sorted(v, key=lambda x: x["value"])
                except TypeError:
                    # Sorting for list with different types: https://stackoverflow.com/a/68416981
                    type_weights = {}
                    for element in v:
                        if type(element["value"]) not in type_weights:
                            type_weights[type(element["value"])] = len(type_weights)

                    generalized_results["results"]["tags"][k] = sorted(
                        v, key=lambda x: (type_weights[type(x["value"])], str(x["value"]))
                    )

        return generalized_results

    def _execute_sample(self, sample, save=False, save_files=False):
        file_path = os.path.join("/tmp", sample.split('_', 1)[0])
        cls = None

        try:
            # Find and unpack sample
            sample_path = self._find_sample(sample)
            unpack_file(sample_path, file_path)

            # Load optional submission parameters
            params_file = os.path.join(self.result_folder, sample, 'params.json')
            if os.path.exists(params_file):
                params = json.load(open(params_file))
            else:
                params = {}

            # Initialize service class
            cls = self.service_class(params.get('config', {}))
            cls.start()

            # Create the service request
            task = Task(self._create_service_task(file_path, params))
            service_request = ServiceRequest(task)

            # Execute the service
            cls.execute(service_request)

            # Get results from the scan
            results = self._generalize_result(task.get_service_result(), task.temp_submission_data)

            # Save results if needs be
            if save:
                # Save results
                result_json = os.path.join(self.result_folder, sample, 'result.json')
                json.dump(results, open(result_json, 'w'), indent=2, allow_nan=False, sort_keys=True)

                if save_files:
                    # Cleanup old extracted and supplementary
                    extracted_dir = os.path.join(self.result_folder, sample, 'extracted')
                    supplementary_dir = os.path.join(self.result_folder, sample, 'supplementary')
                    if os.path.exists(extracted_dir):
                        shutil.rmtree(extracted_dir)
                    if os.path.exists(supplementary_dir):
                        shutil.rmtree(supplementary_dir)

                    # Save extracted files
                    for ext in task.extracted:
                        target_file = os.path.join(self.result_folder, sample, 'extracted', ext['name'])
                        os.makedirs(os.path.dirname(target_file), exist_ok=True)
                        shutil.move(ext['path'], target_file)

                    # Save supplementary files
                    for ext in task.supplementary:
                        target_file = os.path.join(self.result_folder, sample, 'supplementary', ext['name'])
                        os.makedirs(os.path.dirname(target_file), exist_ok=True)
                        shutil.move(ext['path'], target_file)

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

    def compare_sample_results(self, sample, test_extra=False):
        ih = IssueHelper()
        original_results_file = os.path.join(self.result_folder, sample, 'result.json')

        if os.path.exists(original_results_file):
            original_results = json.load(open(original_results_file))
            results = self._execute_sample(sample)

            # Compile the list of issues between the two results
            # Test extra results
            if test_extra and original_results.get('extra', None) != results.get('extra', None):
                ih.add_issue(ih.TYPE_EXTRA, ih.ACTION_CHANGED, "Extra results have changed.")

            # Extracted files
            self._file_compare(
                ih, ih.TYPE_EXTRACTED, original_results['files']['extracted'],
                results['files']['extracted'])
            # Supplementary files
            self._file_compare(ih, ih.TYPE_SUPPLEMENTARY, original_results['files']['supplementary'],
                               results['files']['supplementary'])
            # Heuristics triggered
            self._heuristic_compare(ih, original_results['results']['heuristics'], results['results']['heuristics'])
            # Tags generated
            self._tag_compare(ih, original_results['results']['tags'], results['results']['tags'])
            # Temp submission data generated
            self._temp_data_compare(
                ih, original_results['results']['temp_submission_data'],
                results['results']['temp_submission_data'])
        else:
            ih.append(f"Original result file missing for sample: {sample}")

        return ih

    def run_test_comparison(self, sample, test_extra=False):
        # WARNING: This function is only to be run into a pytest context!
        ih = self.compare_sample_results(sample, test_extra=test_extra)
        if ih.has_issues():
            issues = ih.get_issue_list()
            issues.insert(0, "")
            pytest.fail("\n".join(issues))

    @ staticmethod
    def _heuristic_compare(ih: IssueHelper, original, new):
        oh_map = {x['heur_id']: x for x in original}
        nh_map = {x['heur_id']: x for x in new}
        for heur_id, heur in oh_map.items():
            if heur_id not in nh_map:
                ih.add_issue(ih.TYPE_HEUR, ih.ACTION_MISSING, f"Heuristic #{heur_id} missing from results.")
            else:
                new_heur = nh_map[heur_id]
                for attack_id in heur['attack_ids']:
                    if attack_id not in new_heur['attack_ids']:
                        ih.add_issue(ih.TYPE_HEUR, ih.ACTION_MISSING,
                                     f"Attack ID '{attack_id}' missing from heuristic #{heur_id}.")
                for signature in heur['signatures']:
                    if signature not in new_heur['signatures']:
                        ih.add_issue(ih.TYPE_HEUR, ih.ACTION_MISSING,
                                     f"Signature '{signature}' missing from heuristic #{heur_id}.")

                for attack_id in new_heur['attack_ids']:
                    if attack_id not in heur['attack_ids']:
                        ih.add_issue(ih.TYPE_HEUR, ih.ACTION_ADDED,
                                     f"Attack ID '{attack_id}' added to heuristic #{heur_id}.")
                for signature in new_heur['signatures']:
                    if signature not in heur['signatures']:
                        ih.add_issue(ih.TYPE_HEUR, ih.ACTION_ADDED,
                                     f"Signature '{signature}' added to heuristic #{heur_id}.")

        for heur_id in nh_map.keys():
            if heur_id not in oh_map:
                ih.add_issue(ih.TYPE_HEUR, ih.ACTION_ADDED, f"Heuristic #{heur_id} added to results.")

    @ staticmethod
    def _tag_compare(ih: IssueHelper, original, new):
        for tag_type, tags in original.items():
            if tag_type not in new:
                for t in tags:
                    ih.add_issue(ih.TYPE_TAGS, ih.ACTION_MISSING,
                                 f"Tag '{t['value']} [{tag_type}]' missing from the results.")
            else:
                otm = {x['value']: x for x in tags}
                ntm = {x['value']: x for x in new[tag_type]}
                for v, tag in otm.items():
                    if v not in ntm:
                        ih.add_issue(ih.TYPE_TAGS, ih.ACTION_MISSING,
                                     f"Tag '{v} [{tag_type}]' missing from the results.")
                    else:
                        new_tag = ntm[v]
                        if tag['heur_id'] != new_tag['heur_id']:
                            ih.add_issue(ih.TYPE_TAGS, ih.ACTION_CHANGED,
                                         f"Heuristic ID for tag '{v} [{tag_type}]' has changed.")
                        if tag['signatures'] != new_tag['signatures']:
                            ih.add_issue(ih.TYPE_TAGS, ih.ACTION_CHANGED,
                                         f"Associated signatures for tag '{v} [{tag_type}]' have changed.")

                for v in ntm.keys():
                    if v not in otm:
                        ih.add_issue(ih.TYPE_TAGS, ih.ACTION_ADDED, f"Tag '{v} [{tag_type}]' added to results.")

        for tag_type, tags in new.items():
            if tag_type not in original:
                for t in tags:
                    ih.add_issue(ih.TYPE_TAGS, ih.ACTION_ADDED,
                                 f"Tag '{t['value']} [{tag_type}]' added to the results.")

    @ staticmethod
    def _temp_data_compare(ih: IssueHelper, original, new):
        for k, v in original.items():
            if k not in new:
                ih.add_issue(ih.TYPE_TEMP, ih.ACTION_MISSING,
                             f"Temporary submission data with key '{k}' is missing from the results.")
            elif v != new[k]:
                ih.add_issue(ih.TYPE_TEMP, ih.ACTION_CHANGED,
                             f"Value of temporary submission data with key '{k}' has changed.")

        for k, v in new.items():
            if k not in original:
                ih.add_issue(ih.TYPE_TEMP, ih.ACTION_ADDED,
                             f"Temporary submission data with key '{k}' was added to the results.")

    @ staticmethod
    def _file_compare(ih: IssueHelper, f_type, original, new):
        oh_map = {x['sha256']: x['name'] for x in original}
        on_map = {x['name']: x['sha256'] for x in original}
        nh_map = {x['sha256']: x['name'] for x in new}
        nn_map = {x['name']: x['sha256'] for x in new}

        for sha256, name in oh_map.items():
            if sha256 not in nh_map:
                if name not in nn_map:
                    ih.add_issue(f_type, ih.ACTION_MISSING, f"File '{name} [{sha256}]' missing from the file list.")
                    continue

                if sha256 != nn_map[name]:
                    ih.add_issue(
                        f_type,
                        ih.ACTION_CHANGED,
                        f"The sha256 of the file '{name}' has changed. {sha256} -> {nn_map[name]}"
                    )
                    continue

            if name != nh_map[sha256]:
                ih.add_issue(
                    f_type,
                    ih.ACTION_CHANGED,
                    f"The name of the file '{sha256}' has changed. {name} -> {nh_map[sha256]}"
                )
                continue

        for sha256, name in nh_map.items():
            if sha256 not in oh_map and name not in on_map:
                ih.add_issue(f_type, ih.ACTION_ADDED, f"File '{name} [{sha256}]' added to the file list.")

    def regenerate_results(self, save_files=False):
        for f in self.result_list():
            try:
                self._execute_sample(f, save=True, save_files=save_files)
            except FileMissing:
                print(f"[W] File {f} was not found in any of the following locations: {', '.join(self.locations)}")
