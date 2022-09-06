import os
import pytest

from assemblyline_extra_feature_service.extra_feature import ExtraFeature
from assemblyline_v4_service.testing.helper import TestHelper

# Force manifest location
os.environ['SERVICE_MANIFEST_PATH'] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

# Setup folder locations
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), 'results')
SAMPLES_FOLDER = os.path.join(os.path.dirname(__file__), 'samples')

# Initialize test helper
th = TestHelper(ExtraFeature, RESULTS_FOLDER, SAMPLES_FOLDER)


@pytest.mark.parametrize("sample", th.result_list())
def test_sample(sample):
    th.run_test_comparison(sample)
