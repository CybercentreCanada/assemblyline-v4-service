import os
import pytest

from assemblyline.common.importing import load_module_by_path
from assemblyline_v4_service.testing.helper import TestHelper

# Force manifest location
os.environ['SERVICE_MANIFEST_PATH'] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

# Setup folder locations
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), 'results')
SAMPLES_FOLDER = os.path.join(os.path.dirname(__file__), 'samples')

# Initialize test helper
service_class = load_module_by_path("result_sample.ResultSample", os.path.join(os.path.dirname(__file__), ".."))
th = TestHelper(service_class, RESULTS_FOLDER, SAMPLES_FOLDER)


@pytest.mark.parametrize("sample", th.result_list())
def test_sample(sample):
    # Result sample randomize results therefor it should always have issues
    # th.run_test_comparison(sample) cannot be used in this case
    ih = th.compare_sample_results(sample)
    assert ih.has_issues()
