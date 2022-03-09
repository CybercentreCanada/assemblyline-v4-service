import pytest


class TestTagReducer:
    @staticmethod
    def test_constants():
        from assemblyline_v4_service.common.tag_reducer import NUMBER_REGEX, ALPHA_REGEX, ALPHANUM_REGEX, \
            BASE64_REGEX, DO_NOT_REDUCE
        from regex import compile
        assert NUMBER_REGEX == compile("[0-9]*")
        assert ALPHA_REGEX == compile("[a-zA-Z]*")
        assert ALPHANUM_REGEX == compile("[a-zA-Z0-9]*")
        assert BASE64_REGEX == compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
        assert DO_NOT_REDUCE == ["netloc", "hostname"]

    @staticmethod
    @pytest.mark.parametrize(
        "val, correct_placeholder",
        [
            ("", "${UNKNOWN_TYPE}"),
            ("2", "${NUMBER}"),
            ("a", "${ALPHA}"),
            ("c2hlemxsM3Iz", "${BASE64}"),
            ("a9", "${ALPHA_NUM}"),
            ("some-details-330002341219", "${UNKNOWN_TYPE}"),
        ]
    )
    def test_get_placeholder(val, correct_placeholder):
        from assemblyline_v4_service.common.tag_reducer import _get_placeholder
        assert _get_placeholder(val) == correct_placeholder

    @staticmethod
    @pytest.mark.parametrize(
        "uri_parts, correct_uri",
        [({"path": ["path"],
           "query": {"query": "answer"},
           "scheme": "scheme", "netloc": "domain", "params": "params", "fragment": "fragment"},
          "scheme://domain/path;params?query=a#fragment"),
         ({"path": ["path"],
           "query": "", "scheme": "scheme", "netloc": "domain", "params": "params",
           "fragment": "fragment"},
          "scheme://domain/path;params#fragment"), ])
    def test_turn_back_into_uri(uri_parts, correct_uri):
        from assemblyline_v4_service.common.tag_reducer import _turn_back_into_uri
        assert _turn_back_into_uri(uri_parts) == correct_uri

    @staticmethod
    @pytest.mark.parametrize(
        "uris, correct_tags",
        [(["https://base64encodethis.com/path?base64hash=c2hlemxsM3Iz",
           "https://base64encodethis.com/path?base64hash=YXNkZmVyamdhM2diMCBj",
           "https://base64encodethis.com/path?base64hash=IyQwMjN5di04ICEjIEApIGhcMmJ1cGY5NDMwYTIvNDEyMzIzNCBo", ],
          ["https://base64encodethis.com/path?base64hash=${BASE64}"],),
         (["https://googlelicious.com/somepathother?query=allo",
           "https://googlelicious.com/somepathother?query=mon",
           "https://googlelicious.com/somepathother?query=coco", ],
          ["https://googlelicious.com/somepathother?query=${ALPHA}"],),
         (["https://googlelicious.com/somepath?rng=112431243",
           "https://googlelicious.com/somepath?rng=124312431243",
           "https://googlelicious.com/somepath?rng=22", ],
          ["https://googlelicious.com/somepath?rng=${NUMBER}"],),
         (["https://googlelicious.com/somepath/morepath?rng=112431243&blah=blah",
           "https://googlelicious.com/somepath/morepath?rng=124312431243&blah=blah",
           "https://googlelicious.com/somepath/morepath?rng=22&blah=blah", ],
          ["https://googlelicious.com/somepath/morepath?rng=${NUMBER}&blah=blah"],),
         (["https://websitesname.ca", "https://websitesname.com", "https://websitesname.it", ],
          ["https://websitesname.com", "https://websitesname.ca", "https://websitesname.it", ],),
         (["https://www.facebook.com/some-details-330002341217/",
           "https://www.facebook.com/some-details-330002341218/",
           "https://www.facebook.com/some-details-330002341219/", ],
          ["https://www.facebook.com/${UNKNOWN_TYPE}/"],),
         (["ftp://random1.vib.slx/", "ftp://random2.vib.slx/", "ftp://random3.vib.slx/", ],
          ["ftp://random1.vib.slx", "ftp://random2.vib.slx", "ftp://random3.vib.slx", ],),
         (["https://en.wikipedia.org/wiki/somelink0", "https://en.wikipedia.org/wiki/somelink1",
           "https://en.wikipedia.org/wiki/somelink2", "https://en.wikipedia.org/wiki/somelink3", ],
          ["https://en.wikipedia.org/wiki/${ALPHA_NUM}"],),
         (["https://google.com?query=allo", "https://google.com?query=mon",
           "https://google.com?query=coco", ],
          ["https://google.com?query=${ALPHA}"],),
         (["https://abc.com?query=THISISATESTTHISISATEST",
           "https://def.com?query=THISISATESTTHISISATEST",
           "https://ghi.com?query=THISISATESTTHISISATEST", ],
          ["https://abc.com?query=THISISATESTTHISISATEST",
           "https://def.com?query=THISISATESTTHISISATEST",
           "https://ghi.com?query=THISISATESTTHISISATEST", ],),
         (["https://hello.com/patha?query=THISISATESTTHISISATEST",
           "https://hello.com/pathb?query=THISISATESTTHISISATEST",
           "https://hello.com/pathc?query=THISISATESTTHISISATEST", ],
          ["https://hello.com/${ALPHA}?query=THISISATESTTHISISATEST"],),
         (["https://bonjour.com/path?query=THISISATESTTHISISATEST1",
           "https://bonjour.com/path?query=THISISATESTTHISISATEST1",
           "https://bonjour.com/path?query=THISISATESTTHISISATEST1", ],
          ["https://bonjour.com/path?query=THISISATESTTHISISATEST1"],),
         (["https://hello.com/path?query=THISISATESTTHISISATEST1&rnd=123",
           "https://hello.com/path?query=THISISATESTTHISISATEST1&rnd=345",
           "https://hello.com/path?query=THISISATESTTHISISATEST1&rnd=567", ],
          ["https://hello.com/path?query=THISISATESTTHISISATEST1&rnd=${NUMBER}"],), ])
    def test_reduce_uri_tags(uris, correct_tags):
        from assemblyline_v4_service.common.tag_reducer import reduce_uri_tags
        assert set(reduce_uri_tags(uris)) == set(correct_tags)
