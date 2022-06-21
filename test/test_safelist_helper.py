import pytest


@pytest.mark.parametrize(
    "value, tags, safelist, substring, expected_output",
    [
        ("", [], {}, False, False),
        ("blah", ["network.dynamic.domain"], {}, False, False),
        ("blah", [], {"match": {"network.dynamic.domain": ["google.com"]}}, False, False),
        ("google.com", ["network.dynamic.domain"], {"match": {"network.dynamic.domain": ["google.com"]}}, False,
            True),
        ("google.com", ["network.dynamic.domain"], {"regex": {"network.dynamic.domain": ["google\.com"]}}, False,
            True),
        ("google.com", ["network.dynamic.domain"], {"match": {"network.dynamic.domain": ["www.google.com"]}}, True,
            False),
        ("www.google.com", ["network.dynamic.domain"], {"match": {"network.dynamic.domain": ["google.com"]}}, True,
            True),
        ("www.google.com", ["network.dynamic.domain"], {"blah": {"network.dynamic.domain": ["google.com"]}}, True,
            False),
    ]
)
def test_is_safelisted(value, tags, safelist, substring, expected_output):
    from assemblyline_v4_service.common.safelist_helper import is_tag_safelisted
    assert is_tag_safelisted(value, tags, safelist, substring) == expected_output


@pytest.mark.parametrize(
    "val, expected_return",
    [
        (None, False),
        (b"blah", False),
        ("127.0.0.1", True),
        ("http://blah.adobe.com", True),
        ("play.google.com", True),
        ("blah.com", False)
    ]
)
def test_contains_safelisted_value(val, expected_return):
    from assemblyline_v4_service.common.safelist_helper import contains_safelisted_value
    safelist = {"regex": {"network.dynamic.domain": [".*\.adobe\.com$", "play\.google\.com$"],
                            "network.dynamic.ip": ["(?:127\.|10\.|192\.168|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.).*"]}}
    assert contains_safelisted_value(val, safelist) == expected_return
