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
