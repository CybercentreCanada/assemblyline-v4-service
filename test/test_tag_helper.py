import os
import pytest


SERVICE_CONFIG_NAME = "service_manifest.yml"
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)


def setup_module():
    if not os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        open_manifest = open(TEMP_SERVICE_CONFIG_PATH, "w")
        open_manifest.write("name: Sample\nversion: sample\ndocker_config: \n  image: sample")


def teardown_module():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)


@pytest.mark.parametrize(
    "value, expected_tags, tags_were_added",
    [
        ("", {}, False),
        ("blah", {"blah": ["blah"]}, True),
        ([], {}, False),
        (["blah"], {"blah": ["blah"]}, True),
        (["blah", "blahblah"], {"blah": ["blah", "blahblah"]}, True)
    ]
)
def test_add_tag(value, expected_tags, tags_were_added):
    from assemblyline_v4_service.common.result import ResultSection
    from assemblyline_v4_service.common.tag_helper import add_tag
    res_sec = ResultSection("blah")
    tag = "blah"
    safelist = {"match": {"domain": ["blah.ca"]}}
    assert add_tag(res_sec, tag, value, safelist) == tags_were_added
    assert res_sec.tags == expected_tags


def test_get_regex_for_tag():
    from assemblyline.odm.base import DOMAIN_ONLY_REGEX, URI_PATH, FULL_URI, IP_REGEX
    from assemblyline_v4_service.common.tag_helper import _get_regex_for_tag
    assert _get_regex_for_tag("network.dynamic.domain") == DOMAIN_ONLY_REGEX
    assert _get_regex_for_tag("network.dynamic.ip") == IP_REGEX
    assert _get_regex_for_tag("network.dynamic.uri") == FULL_URI
    assert _get_regex_for_tag("network.dynamic.uri_path") == URI_PATH
    assert _get_regex_for_tag("network.port") is None


@pytest.mark.parametrize(
    "tag, value, expected_tags, added_tag",
    [
        # Empty values
        ("", "", {}, False),
        ("blah", "", {}, False),
        # Normal run without regex match
        ("blah", "blah", {"blah": ["blah"]}, True),
        # Normal run with regex match
        ("uri_path", "/blah", {"uri_path": ["/blah"]}, True),
        # No regex match for ip
        ("ip", "blah", {}, False),
        # Regex match for ip
        ("ip", "1.1.1.1", {"ip": ["1.1.1.1"]}, True),
        # No regex match for domain
        ("domain", "blah", {}, False),
        # Regex match but not valid domain
        ("domain", "blah.blah", {}, False),
        # Regex match, but FP found
        ("domain", "microsoft.net", {}, False),
        # Regex match, but FP found
        ("domain", "blah.py", {}, False),
        # Safelisted value
        ("domain", "blah.ca", {}, False),
        # URI with invalid domain
        ("uri", "http://blah.blah/blah", {"uri": ["http://blah.blah/blah"]}, True),
        # URI with valid domain
        ("uri", "http://blah.com/blah", {"uri": ["http://blah.com/blah"], "network.dynamic.domain": ["blah.com"]}, True),
        # URI with valid IP
        ("uri", "http://1.1.1.1/blah", {"uri": ["http://1.1.1.1/blah"], "network.dynamic.ip": ["1.1.1.1"]}, True),
    ]
)
def test_validate_tag(tag, value, expected_tags, added_tag):
    from assemblyline_v4_service.common.result import ResultSection
    from assemblyline_v4_service.common.tag_helper import add_tag
    res_sec = ResultSection("blah")
    safelist = {"match": {"domain": ["blah.ca"]}}
    assert add_tag(res_sec, tag, value, safelist) == added_tag
    assert res_sec.tags == expected_tags
