import pytest

from assemblyline_v4_service.common.result import _pack_tags, _unpack_tags


@pytest.mark.parametrize(
    "tags",
    [
        {"file.string.blacklisted": ["pear", "apple", "banana"]},
        {"file.string.blacklisted": ["first", "second"]},
        {"file.string.blacklisted": ["second", "first"]},
    ],
)
def test_pack_unpack_identity(tags):
    assert _unpack_tags(_pack_tags(tags)) == tags
