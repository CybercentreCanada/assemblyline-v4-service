import os

from pprint import pprint
from assemblyline_result_sample_service.result_sample import ResultSample
from assemblyline_v4_service.testing.helper import TestHelper


def test_sample():
    os.environ['SERVICE_MANIFEST_PATH'] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")
    file_to_test = "87bcfad697742459387d54d11a090283027df97055decf1bef813610ab09ff80"
    th = TestHelper(
        ResultSample,
        os.path.join(os.path.dirname(__file__), 'results'),
        [os.path.join(os.path.dirname(__file__), 'samples')])

    pprint(th._execute_sample(file_to_test, save=True))


if __name__ == "__main__":
    test_sample()
