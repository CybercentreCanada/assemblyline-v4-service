import pytest
import os

SERVICE_CONFIG_NAME = "service_manifest.yml"
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)


def setup_module():
    if not os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        open_manifest = open(TEMP_SERVICE_CONFIG_PATH, "w")
        open_manifest.write("name: Sample\nversion: sample\ndocker_config: \n  image: sample")


def teardown_module():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)


class TestSectionReducer:
    @staticmethod
    def test_reduce():
        from assemblyline_v4_service.common.section_reducer import reduce
        from assemblyline_v4_service.common.result import Result, ResultSection
        res = Result()
        result_section = ResultSection("blah")
        res.add_section(result_section)
        reduce(res)
        # Code coverage only
        assert True

    @staticmethod
    @pytest.mark.parametrize("tags, correct_tags",
                             [({
                                 "network.dynamic.uri":
                                 ["https://google.com?query=allo", "https://google.com?query=mon",
                                  "https://google.com?query=coco"]},
                               {"network.dynamic.uri": ["https://google.com?query=${ALPHA}"]},), ])
    def test_section_traverser(tags, correct_tags):
        from assemblyline_v4_service.common.section_reducer import _section_traverser
        from assemblyline_v4_service.common.result import ResultSection
        section = ResultSection("blah")
        subsection = ResultSection("subblah")
        for key, values in tags.items():
            for value in values:
                subsection.add_tag(key, value)
        section.add_subsection(subsection)
        assert _section_traverser(section).subsections[0].tags == correct_tags

    @staticmethod
    @pytest.mark.parametrize("tags, correct_reduced_tags",
                             [(None, {}),
                              ({
                                  "network.dynamic.uri":
                                  ["https://google.com?query=allo", "https://google.com?query=mon",
                                   "https://google.com?query=coco"]},
                               {"network.dynamic.uri": ["https://google.com?query=${ALPHA}"]}),
                              ({
                                  "network.static.uri":
                                  ["https://google.com?query=allo", "https://google.com?query=mon",
                                   "https://google.com?query=coco"]},
                               {"network.static.uri": ["https://google.com?query=${ALPHA}"]}),
                              ({"network.dynamic.uri_path": ["/blah/123", "/blah/321"]},
                               {"network.dynamic.uri_path": ["/blah/${NUMBER}"]}),
                              ({"network.static.uri_path": ["/blah/123", "/blah/321"]},
                               {"network.static.uri_path": ["/blah/${NUMBER}"]}),
                              ({"attribution.actor": ["MALICIOUS_ACTOR"]},
                               {"attribution.actor": ["MALICIOUS_ACTOR"]}), ])
    def test_reduce_specific_tags(tags, correct_reduced_tags):
        from assemblyline_v4_service.common.section_reducer import _reduce_specific_tags
        assert _reduce_specific_tags(tags) == correct_reduced_tags
