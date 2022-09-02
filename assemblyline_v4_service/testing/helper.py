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

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SELF_LOCATION = os.environ.get("FULL_SELF_LOCATION", ROOT_DIR)
SAMPLES_LOCATION = os.environ.get("FULL_SAMPLES_LOCATION", None)
[SELF_LOCATION, SAMPLES_LOCATION]


def _list_results(location):
    return [f.rstrip(".json") for f in os.listdir(os.path.join(location, "tests", "results"))]


class TestHelper:
    def __init__(self, service_class, result_folder, extra_sample_locations=None):
        if not extra_sample_locations:
            extra_sample_locations = []

        # Set service class to use
        self.service_class = service_class

        # Set location for samples
        self.locations = extra_sample_locations
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
