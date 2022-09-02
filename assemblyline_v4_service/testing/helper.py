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
    def _generalize_result(result):
        # At first we were comparing the full result and removing the random/unpredictable information.
        # Now we are only keeping the strict minimum to compare with.
        # supplementary/extracted sha256 + heuristics heur_id + tags
        trimed_result = {}
        if "response" in result:
            trimed_result["response"] = {}
            if "supplementary" in result["response"]:
                trimed_result["response"]["supplementary"] = sorted(
                    [x["sha256"] for x in result["response"]["supplementary"]]
                )
            if "extracted" in result["response"]:
                trimed_result["response"]["extracted"] = sorted(
                    [{"name": x["name"], "sha256": x["sha256"]} for x in result["response"]["extracted"]],
                    key=lambda x: x["sha256"],
                )

        if "result" in result:
            trimed_result["result"] = {}
            if "sections" in result["result"]:
                trimed_result["result"] = {"heuristics": [], "tags": {}}
                for section in result["result"]["sections"]:
                    if "heuristic" in section:
                        if section["heuristic"] is not None:
                            if "heur_id" in section["heuristic"]:
                                trimed_result["result"]["heuristics"].append(section["heuristic"]["heur_id"])
                    if "tags" in section:
                        if section["tags"]:
                            for k, v in flatten(section["tags"]).items():
                                if k in trimed_result["result"]["tags"]:
                                    trimed_result["result"]["tags"][k].extend(v)
                                else:
                                    trimed_result["result"]["tags"][k] = v

                # Sort the heur_id and tags lists so they always appear in the same order even if
                # the result sections where moved around.
                trimed_result["result"]["heuristics"] = sorted(trimed_result["result"]["heuristics"])
                for k, v in trimed_result["result"]["tags"].items():
                    trimed_result["result"]["tags"][k] = sorted(v)

        return trimed_result

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

            results = self._generalize_result(task.get_service_result())

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
