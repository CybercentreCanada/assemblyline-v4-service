import errno
import json
import os
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
        # TODO: load temp_submission_data, metadata and other service tags
        self.submission_params = helper.get_service_attributes().submission_params

    def _create_service_task(self, file_path):
        fileinfo_keys = ["magic", "md5", "mime", "sha1", "sha256", "size", "type"]

        return ServiceTask(
            {
                "sid": 1,
                "metadata": {},
                "deep_scan": False,
                "service_name": "Not Important",
                "service_config": {param.name: param.default for param in self.submission_params},
                "fileinfo": {k: v for k, v in self.identify.fileinfo(file_path).items() if k in fileinfo_keys},
                "filename": os.path.basename(file_path),
                "min_classification": "TLP:WHITE",
                "max_files": 501,
                "ttl": 3600,
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
                "attack": {},
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
            sample_path = self._find_sample(sample)
            unpack_file(sample_path, file_path)

            cls = self.service_class()
            cls.start()

            task = Task(self._create_service_task(file_path))
            service_request = ServiceRequest(task)

            cls.execute(service_request)

            results = self._generalize_result(task.get_service_result(), task.temp_submission_data)

            if save:
                result_json = os.path.join(self.result_folder, sample, 'result.json')
                json.dump(results, open(result_json, 'w'), indent=2, allow_nan=False, sort_keys=True)

            return results
        finally:
            if cls:
                cls._cleanup()
            if os.path.exists(file_path):
                os.remove(file_path)

    def result_list(self):
        return [f for f in os.listdir(self.result_folder)
                if len(f.split("_")[0]) == 64 and os.path.isdir(os.path.join(self.result_folder, f))]

    def compare_sample_results(self, sample):
        original_results_file = os.path.join(self.result_folder, sample, 'result.json')

        if os.path.exists(original_results_file):
            original_results = json.load(open(original_results_file))
            results = self._execute_sample(sample)
            assert original_results == results

    def regenerate_results(self):
        for f in self.result_list():
            try:
                self._execute_sample(f, save=True)
            except FileNotFoundError:
                print(f"[W] File {f} was not for in any of the following locations: {', '.join(self.locations)}")
