from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common.task import Task
from assemblyline_v4_service.common.result import (
    BODY_FORMAT, DividerSectionBody, GraphSectionBody, Heuristic, ImageSectionBody, InvalidFunctionException,
    InvalidHeuristicException, JSONSectionBody, KVSectionBody, MemorydumpSectionBody, MultiSectionBody,
    OrderedKVSectionBody, ProcessItem, ProcessTreeSectionBody, Result, ResultAggregationException, ResultGraphSection,
    ResultImageSection, ResultJSONSection, ResultKeyValueSection, ResultMemoryDumpSection, ResultMultiSection,
    ResultOrderedKeyValueSection, ResultProcessTreeSection, ResultSection, ResultTableSection, ResultTextSection,
    ResultTimelineSection, ResultURLSection, SectionBody, TableRow, TableSectionBody, TextSectionBody,
    TimelineSectionBody, TypeSpecificResultSection, URLSectionBody, get_heuristic_primitives)
from assemblyline_v4_service.common.request import ServiceRequest
import pytest
import os
import tempfile
from test.test_common import TESSERACT_LIST, setup_module

# Ensure service manifest is instantiated before importing from OCR submodule
setup_module()


@pytest.fixture
def heuristic():
    return Heuristic(1)


@pytest.fixture
def sectionbody():
    return SectionBody("blah")


@pytest.fixture
def service_request():
    st = ServiceTask({
        "service_config": {},
        "metadata": {},
        "min_classification": "",
        "fileinfo": {
            "magic": "blah",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "size": 0,
            "type": "text/plain",
        },
        "filename": "blah",
        "service_name": "blah",
        "max_files": 0,
    })
    t = Task(st)
    service_request = ServiceRequest(t)
    return service_request


def test_get_heuristic_primitives(heuristic):
    # No heuristic
    assert get_heuristic_primitives(None) is None

    # Heuristic
    assert get_heuristic_primitives(heuristic) == {
        'attack_ids': ["T1005"],
        'frequency': 1,
        'heur_id': 1,
        'score': 250,
        'score_map': {},
        'signatures': {},
    }


def test_heuristic_init(heuristic):
    # Heuristic does not exist
    with pytest.raises(InvalidHeuristicException):
        Heuristic(2)

    # Heuristic exists
    assert get_heuristic_primitives(heuristic) == {
        'attack_ids': ["T1005"],
        'frequency': 1,
        'heur_id': 1,
        'score': 250,
        'score_map': {},
        'signatures': {},
    }

    # Heuristic with additional agruments
    h = Heuristic(
        1, attack_id="T1001", signature="blah", attack_ids=["T1002", "T123"],
        signatures={"a": 1, "b": 2}, frequency=3, score_map={"c": 3, "a": 100}
    )
    assert get_heuristic_primitives(h) == {
        'attack_ids': ["T1560", "T1001"],
        'frequency': 0,
        'heur_id': 1,
        'score': 1200,
        'score_map': {"a": 100, "c": 3},
        'signatures': {"a": 1, "b": 2, "blah": 3},
    }


def test_heuristic_attack_ids(heuristic):
    assert heuristic.attack_ids == ["T1005"]


def test_heuristic_description(heuristic):
    assert heuristic.description == "blah"


def test_heuristic_frequency(heuristic):
    assert heuristic.frequency == 1


def test_heuristic_heur_id(heuristic):
    assert heuristic.heur_id == 1


def test_heuristic_name(heuristic):
    assert heuristic.name == "blah"


def test_heuristic_score():
    heuristic = Heuristic(
        1, signature="blah", signatures={"a": 1, "b": 2}, frequency=3, score_map={"c": 3, "a": 100}
    )
    assert heuristic.score == 1200


def test_heuristic_score_map():
    heuristic = Heuristic(
        1, score_map={"c": 3, "a": 100}
    )
    assert heuristic.score_map == {"c": 3, "a": 100}


def test_heuristic_signatures():
    heuristic = Heuristic(
        1, signatures={"a": 1, "b": 2}
    )
    assert heuristic.signatures == {"a": 1, "b": 2}


def test_heuristic_add_attack_id(heuristic):
    # Attack ID is not in the _attack_ids
    heuristic.add_attack_id("T1001")
    assert heuristic._attack_ids == ["T1005", "T1001"]

    # Attack ID is in the _attack_ids
    heuristic.add_attack_id("T1001")
    assert heuristic._attack_ids == ["T1005", "T1001"]

    # Attack ID is in the revoke_map
    heuristic.add_attack_id("T1002")
    assert heuristic._attack_ids == ["T1005", "T1001", "T1560"]

    # Attack ID is in the revoke_map and updated Attack ID is already in _attack_ids
    heuristic.add_attack_id("T1022")
    assert heuristic._attack_ids == ["T1005", "T1001", "T1560"]

    # Invalid Attack ID
    heuristic.add_attack_id("T123")
    assert heuristic._attack_ids == ["T1005", "T1001", "T1560"]


def test_heuristic_add_signature_id(heuristic):
    # Add the first signature
    heuristic.add_signature_id("blah")
    assert heuristic._signatures == {"blah": 1}

    # Add it again
    heuristic.add_signature_id("blah")
    assert heuristic._signatures == {"blah": 2}

    # Check the _score_map
    assert heuristic._score_map == {}

    # Set a score
    heuristic.add_signature_id("blah", 100)
    assert heuristic._signatures == {"blah": 3}
    assert heuristic._score_map == {"blah": 100}


def test_heuristic_increment_frequency(heuristic):
    # Default frequency
    assert heuristic._frequency == 1

    # Incremented frequency
    heuristic.increment_frequency()
    assert heuristic._frequency == 2


def test_sectionbody_init(sectionbody):
    assert sectionbody._format == "blah"
    assert sectionbody._data is None
    assert sectionbody._config == {}


def test_sectionbody_format(sectionbody):
    assert sectionbody.format == "blah"


def test_sectionbody_body(sectionbody):
    # No sectionbody._data
    assert sectionbody.body is None

    # sectionbody._data is a str
    sectionbody._data = "blah"
    assert sectionbody.body == "blah"

    # sectionbody._data is a str
    sectionbody._data = {"blah": "blah"}
    assert sectionbody.body == '{"blah": "blah"}'


def test_sectionbody_config(sectionbody):
    assert sectionbody.config == {}


def test_sectionbody_set_body(sectionbody):
    sectionbody.set_body("blah")
    assert sectionbody._data == "blah"


def test_textsectionbody_init():
    # No body
    tsb = TextSectionBody()
    assert tsb._format == BODY_FORMAT.TEXT
    assert tsb.body is None

    # Some body
    tsb = TextSectionBody("blah")
    assert tsb._format == BODY_FORMAT.TEXT
    assert tsb.body == "blah"


def test_textsectionbody_add_line():
    tsb = TextSectionBody()

    # Line to add
    assert tsb.add_line("blah") == "blah"

    # Line as list to add
    assert tsb.add_line(["blah", "blah"]) == "blah\nblahblah"

    # Attempt to add a None-value
    with pytest.raises(ValueError):
        tsb.add_line(None)

    # Add an empty string value
    assert tsb.add_line("") == "blah\nblahblah\n"


def test_textsectionbody_add_lines():
    tsb = TextSectionBody()

    # No line to add
    assert tsb.add_lines(None) is None

    # Invalid type
    assert tsb.add_lines("blah") is None

    # Line as list to add
    assert tsb.add_lines(["blah", "blah"]) == "blah\nblah"

    # Add another list
    assert tsb.add_lines(["blah"]) == "blah\nblah\nblah"


def test_memorydumpsectionbody_init():
    # No body
    msb = MemorydumpSectionBody()
    assert msb._format == BODY_FORMAT.MEMORY_DUMP
    assert msb.body is None

    # Some body
    msb = MemorydumpSectionBody("blah")
    assert msb._format == BODY_FORMAT.MEMORY_DUMP
    assert msb.body == "blah"


def test_urlsectionbody_init():
    # No body
    usb = URLSectionBody()
    assert usb._format == BODY_FORMAT.URL
    assert usb._data == []


def test_urlsectionbody_add_url():
    usb = URLSectionBody()

    # No url
    with pytest.raises(ValueError):
        usb.add_url("")

    # No name
    assert usb.add_url("blah") is None
    assert usb._data == [{"url": "blah"}]

    usb._data.clear()

    # Name
    assert usb.add_url("blah", "blah") is None
    assert usb._data == [{"url": "blah", "name": "blah"}]


def test_graphsectionbody_init():
    # No body
    gsb = GraphSectionBody()
    assert gsb._format == BODY_FORMAT.GRAPH_DATA
    assert gsb._data is None


def test_graphsectionbody_set_colormap():
    gsb = GraphSectionBody()

    # Some basic values
    assert gsb.set_colormap(0, 0, []) is None
    assert gsb._data == {'data': {'domain': [0, 0], 'values': []}, 'type': 'colormap'}


def test_kvsectionbody_init():
    kvsb = KVSectionBody()

    # No body
    assert kvsb._format == BODY_FORMAT.KEY_VALUE
    assert kvsb._data == {}

    # Some body
    kvsb = KVSectionBody(a="b")
    assert kvsb._data == {"a": "b"}


def test_kvsectionbody_set_item():
    kvsb = KVSectionBody()

    assert kvsb.set_item("a", "b") is None
    assert kvsb._data == {"a": "b"}


def test_kvsectionbody_update_items():
    kvsb = KVSectionBody()

    assert kvsb.update_items({"a": "b"}) is None
    assert kvsb._data == {"a": "b"}


def test_orderedkvsectionbody_init():
    okvsb = OrderedKVSectionBody()

    # No body
    assert okvsb._format == BODY_FORMAT.ORDERED_KEY_VALUE
    assert okvsb._data == []

    # Some body
    okvsb = OrderedKVSectionBody(a="b")
    assert okvsb._format == BODY_FORMAT.ORDERED_KEY_VALUE
    assert okvsb._data == [("a", "b")]


def test_orderedkvsectionbody_add_item():
    okvsb = OrderedKVSectionBody()

    assert okvsb.add_item(None, None) is None
    assert okvsb._data == [('None', None)]


def test_jsonsectionbody_init():
    jsb = JSONSectionBody()

    assert jsb._format == BODY_FORMAT.JSON
    assert jsb._data == {}


def test_jsonsectionbody_set_json():
    jsb = JSONSectionBody()

    # No body
    assert jsb.set_json({}) is None
    assert jsb._data == {}

    # Some body
    assert jsb.set_json({"a": "b"}) is None
    assert jsb._data == {"a": "b"}

    # Override
    assert jsb.set_json({"b": "c"}) is None
    assert jsb._data == {"b": "c"}


def test_jsonsectionbody_update_json():
    jsb = JSONSectionBody()

    # No body
    assert jsb.update_json({}) is None
    assert jsb._data == {}

    # Some body
    assert jsb.update_json({"a": "b"}) is None
    assert jsb._data == {"a": "b"}

    # Update
    assert jsb.update_json({"b": "c"}) is None
    assert jsb._data == {"a": "b", "b": "c"}


def test_processitem_init():
    # Default values
    pi = ProcessItem(123, "blah", "blah")

    assert pi.pid == 123
    assert pi.name == "blah"
    assert pi.cmd == "blah"
    assert pi.network_count == 0
    assert pi.file_count == 0
    assert pi.registry_count == 0
    assert pi.safelisted is False
    assert pi.signatures == {}
    assert pi.children == []

    # All args
    pi = ProcessItem(123, "blah", "blah", {"a": 1}, [ProcessItem(321, "test", "test")], 3, 4, 5, True)

    assert pi.pid == 123
    assert pi.name == "blah"
    assert pi.cmd == "blah"
    assert pi.network_count == 3
    assert pi.file_count == 4
    assert pi.registry_count == 5
    assert pi.safelisted is True
    assert pi.signatures == {"a": 1}
    assert len(pi.children) == 1 and isinstance(pi.children[0], ProcessItem)


def test_processitem_add_signature():
    pi = ProcessItem(123, "blah", "blah")
    assert pi.signatures == {}

    pi.add_signature("blah", 1)
    assert pi.signatures == {"blah": 1}


def test_processitem_add_child_process():
    pi = ProcessItem(123, "blah", "blah")
    assert pi.children == []

    pi.add_child_process(ProcessItem(321, "test", "test"))
    assert len(pi.children) == 1 and isinstance(pi.children[0], ProcessItem)


def test_processitem_add_network_events():
    pi = ProcessItem(123, "blah", "blah")
    assert pi.network_count == 0

    with pytest.raises(ValueError):
        pi.add_network_events(-1)

    pi.add_network_events(2)
    assert pi.network_count == 2


def test_processitem_add_file_events():
    pi = ProcessItem(123, "blah", "blah")
    assert pi.file_count == 0

    with pytest.raises(ValueError):
        pi.add_file_events(-1)

    pi.add_file_events(2)
    assert pi.file_count == 2


def test_processitem_add_registry_events():
    pi = ProcessItem(123, "blah", "blah")
    assert pi.registry_count == 0

    with pytest.raises(ValueError):
        pi.add_registry_events(-1)

    pi.add_registry_events(2)
    assert pi.registry_count == 2


def test_processitem_safelist():
    pi = ProcessItem(123, "blah", "blah")
    assert pi.safelisted is False

    pi.safelist()
    assert pi.safelisted is True


def test_processitem_as_primitives():
    pi = ProcessItem(123, "blah", "blah", {"a": 1}, [ProcessItem(321, "test", "test")], 3, 4, 5, True)
    assert pi.as_primitives() == {
        'children': [
            {
                'children': [],
                'command_line': 'test',
                'file_count': 0,
                'network_count': 0,
                'process_name': 'test',
                'process_pid': 321,
                'registry_count': 0,
                'safelisted': False,
                'signatures': {}
            }
        ],
        'command_line': 'blah',
        'file_count': 4,
        'network_count': 3,
        'process_name': 'blah',
        'process_pid': 123,
        'registry_count': 5,
        'safelisted': True,
        'signatures': {'a': 1},
    }


def test_processtreesectionbody_init():
    ptsb = ProcessTreeSectionBody()
    assert ptsb._format == BODY_FORMAT.PROCESS_TREE
    assert ptsb._data == []


def test_processtreesectionbody_add_process():
    ptsb = ProcessTreeSectionBody()
    pi = ProcessItem(123, "blah", "blah")
    assert ptsb.add_process(pi) is None
    assert ptsb._data == [
        {
            'children': [],
            'command_line': 'blah',
            'file_count': 0,
            'network_count': 0,
            'process_name': 'blah',
            'process_pid': 123,
            'registry_count': 0,
            'safelisted': False,
            'signatures': {}
        },
    ]


def test_tablerow_init():
    tr = TableRow()
    assert tr == {}

    tr = TableRow(a="b")
    assert tr == {"a": "b"}

    tr = TableRow({"a": "c"}, {"b": "c"})
    assert tr == {"a": "c", "b": "c"}


def test_tablesectionbody_init():
    tsb = TableSectionBody()

    assert tsb._format == BODY_FORMAT.TABLE
    assert tsb._data == []


def test_tablesectionbody_add_row():
    tsb = TableSectionBody()

    # Empty row
    tr = TableRow()
    assert tsb.add_row(tr) is None
    assert tsb._data == []
    assert tsb._config == {}

    # Row with data
    tr = TableRow(a="b")
    assert tsb.add_row(tr) is None
    assert tsb._data == [{"a": "b"}]
    assert tsb._config == {"column_order": ["a"]}

    # Overwrite column_order
    tr = TableRow(b="c", d="e")
    assert tsb.add_row(tr) is None
    assert tsb._data == [{"a": "b"}, {"b": "c", "d": "e"}]
    assert tsb._config == {"column_order": ["b", "d"]}


def test_tablesectionbody_set_column_order():
    tsb = TableSectionBody()

    # Empty order
    assert tsb.set_column_order([]) is None
    assert tsb._config == {}

    # Some order
    assert tsb.set_column_order(["a"]) is None
    assert tsb._config == {"column_order": ["a"]}


def test_imagesectionbody_init(service_request):
    isb = ImageSectionBody(service_request)

    assert isb._request == service_request
    assert isb._format == BODY_FORMAT.IMAGE
    assert isb._data == []


@pytest.mark.skipif(len(TESSERACT_LIST) < 1, reason="Requires tesseract-ocr apt package")
def test_imagesectionbody_add_image(service_request):
    isb = ImageSectionBody(service_request)
    image_path = os.path.join(
        os.path.dirname(__file__),
        "b32969aa664e3905c20f865cdd7b921f922678f5c3850c78e4c803fbc1757a8e")

    # Basic
    assert isb.add_image(image_path, "image_name", "description of image") is None
    assert isb._data == [
        {'img': {
            'name': 'image_name',
            'sha256': '09bf99ab5431af13b701a06dc2b04520aea9fd346584fa2a034d6d4af0c57329',
            'description': 'description of image'},
         'thumb': {
             'name': 'image_name.thumb',
             'sha256': '1af0e0d99845493b64cf402b3704170f17ecf15001714016e48f9d4854218901',
             'description': 'description of image (thumbnail)'}}]

    isb._data.clear()

    # Classification, OCR heuristic, OCR_IO, image with no password
    ocr_heuristic_id = 1
    _, path = tempfile.mkstemp()
    ocr_io = open(path, "w")
    assert isb.add_image(image_path, "image_name", "description of image", "TLP:A", ocr_heuristic_id,
                         ocr_io).body == '{"ransomware": ["YOUR FILES HAVE BEEN ENCRYPTED AND YOU WON\'T BE ABLE TO ' \
                                         'DECRYPT THEM.", "YOU CAN BUY DECRYPTION SOFTWARE FROM US, THIS SOFTWARE ' \
                                         'WILL ALLOW YOU TO RECOVER ALL OF YOUR DATA AND", "RANSOMWARE FROM YOUR ' \
                                         'COMPUTER. THE PRICE OF THE SOFTWARE IS $.2..%.. PAYMENT CAN BE MADE IN ' \
                                         'BITCOIN OR XMR.", "How 00! PAY, WHERE DO | GET BITCOIN OR XMR?", "YOURSELF ' \
                                         'TO FIND OUT HOW TO BUY BITCOIN OR XMR.", "PAYMENT INFORMATION: SEND $15, ' \
                                         'TO ONE OF OUR CRYPTO ADDRESSES, THEN SEND US EMAIL WITH PAYMENT", ' \
                                         '"CONFIRMATION AND YOU\'LL GET THE DECRYPTION SOFTWARE IN EMAIL.", ' \
                                         '"BTC ADDRESS : bciqsht77cpgw7kv420r4secmu88g34wvn96dsyc5s"]}'
    assert isb._data == [
        {'img': {
            'name': 'image_name',
            'sha256': '09bf99ab5431af13b701a06dc2b04520aea9fd346584fa2a034d6d4af0c57329',
            'description': 'description of image'},
         'thumb': {
            'name': 'image_name.thumb',
            'sha256': '1af0e0d99845493b64cf402b3704170f17ecf15001714016e48f9d4854218901',
            'description': 'description of image (thumbnail)'}}]


    # Ensure that the image files added are marked as `is_image_section`
    image_hashes = [img['sha256'] for img in isb._data[0].values()]
    for file in service_request.task.supplementary:
        if file['sha256'] in image_hashes:
            assert(file['is_section_image'])

def test_multisectionbody_init():
    msb = MultiSectionBody()

    assert msb._format == BODY_FORMAT.MULTI
    assert msb._data == []


def test_multisectionbody_add_section_body():
    msb = MultiSectionBody()

    msb.add_section_body(TextSectionBody("blah"))
    msb.add_section_body(GraphSectionBody())

    assert len(msb._data) == 2
    assert msb._data == [(BODY_FORMAT.TEXT, "blah", {}), (BODY_FORMAT.GRAPH_DATA, None, {})]


def test_dividersectionbody_init():
    dsb = DividerSectionBody()

    assert dsb._format == BODY_FORMAT.DIVIDER
    assert dsb._data is None


def test_timelinesectionbody_init():
    tsb = TimelineSectionBody()

    assert tsb._format == BODY_FORMAT.TIMELINE
    assert tsb._data == []


def test_timelinesectionbody_add_node():
    tsb = TimelineSectionBody()

    tsb.add_node("title", "content", "opposite_content")
    assert tsb._format == BODY_FORMAT.TIMELINE
    assert tsb._data == [{'title': 'title', 'content': 'content',
                          'opposite_content': 'opposite_content', 'icon': None, 'signatures': [], 'score': 0}]


def test_resultsection_init():
    # Default
    rs = ResultSection("title_text_as_str")
    assert rs._finalized is False
    assert rs.parent is None
    assert rs._section is None
    assert rs._subsections == []
    assert rs._body_format == BODY_FORMAT.TEXT
    assert rs._body is None
    assert rs._body_config == {}
    assert rs.classification == 'TLP:C'
    assert rs.depth == 0
    assert rs._tags == {}
    assert rs._heuristic is None
    assert rs.zeroize_on_tag_safe is False
    assert rs.auto_collapse is False
    assert rs.zeroize_on_sig_safe is True
    assert rs.title_text == 'title_text_as_str'

    # Title text as a list
    rs = ResultSection(["title", "text", "as", "list"])
    assert rs.title_text == "titletextaslist"

    # Body as a string
    rs = ResultSection("title_text_as_str", body="blah")
    assert rs._body_format == BODY_FORMAT.TEXT
    assert rs._body_config == {}
    assert rs._body == "blah"

    # Body as a SectionBody
    tsb = TableSectionBody()
    tr = TableRow(a="b")
    tsb.add_row(tr)
    rs = ResultSection("title_text_as_str", body=tsb)
    assert rs._body_format == BODY_FORMAT.TABLE
    assert rs._body_config == {'column_order': ['a']}
    assert rs._body == '[{"a": "b"}]'

    # Non-defaults
    heur = Heuristic(1)
    rs = ResultSection(
        "title_text_as_str",
        classification="TLP:AMBER",
        body_format=BODY_FORMAT.GRAPH_DATA,
        heuristic=heur,
        tags={"a": "b"},
        zeroize_on_tag_safe=True,
        auto_collapse=True,
        zeroize_on_sig_safe=False
    )

    assert rs._body_format == BODY_FORMAT.GRAPH_DATA
    assert rs._body_config == {}
    assert rs.classification == 'TLP:AMBER'
    assert get_heuristic_primitives(rs._heuristic) == {'heur_id': 1, 'score': 250, 'attack_ids': [
        'T1005'], 'signatures': {}, 'frequency': 1, 'score_map': {}}
    assert rs._tags == {"a": "b"}
    assert rs.zeroize_on_tag_safe is True
    assert rs.auto_collapse is True
    assert rs.zeroize_on_sig_safe is False

    # Set parent as ResultSection
    parent = ResultSection("parent")
    rs = ResultSection("title_text_as_str", parent=parent)
    assert rs.parent == parent
    assert len(parent.subsections) == 1
    assert parent.subsections[0] == rs

    # Set parent as Result
    parent = Result()
    rs = ResultSection("title_text_as_str", parent=parent)
    assert rs.parent == parent
    assert len(parent.sections) == 1
    assert parent.sections[0] == rs

    # Invalid heuristic
    rs = ResultSection("title_text_as_str", heuristic="blah")
    assert rs._heuristic is None


def test_resultsection_body():
    rs = ResultSection("title_text_as_str")
    assert rs.body is None


def test_resultsection_body_format():
    rs = ResultSection("title_text_as_str")
    assert rs.body_format == BODY_FORMAT.TEXT


def test_resultsection_body_config():
    rs = ResultSection("title_text_as_str")
    assert rs.body_config == {}


def test_resultsection_heuristic():
    rs = ResultSection("title_text_as_str")
    assert rs.heuristic is None


def test_resultsection_subsections():
    rs = ResultSection("title_text_as_str")
    assert rs.subsections == []


def test_resultsection_tags():
    rs = ResultSection("title_text_as_str")
    assert rs.tags == {}


def test_resultsection_add_line():
    rs = ResultSection("title_text_as_str")

    # Add line as string
    assert rs.add_line("blah") is None
    assert rs._body == "blah"

    # Add another line as string
    assert rs.add_line("blah") is None
    assert rs._body == "blah\nblah"

    # Add a list of strings
    assert rs.add_line(["a", "b"]) is None
    assert rs._body == "blah\nblah\nab"

    # Attempt to add a None-value
    with pytest.raises(ValueError):
        rs.add_line(None)

    # Add an empty string value
    assert rs.add_line("") is None
    assert rs._body == "blah\nblah\nab\n"


def test_resultsection_add_lines():
    rs = ResultSection("title_text_as_str")

    # Add non-list
    assert rs.add_lines("blah") is None
    assert rs._body is None

    # Add list
    assert rs.add_lines(["blah"]) is None
    assert rs._body == "blah"

    # Add another list
    assert rs.add_lines(["blah", "blah"]) is None
    assert rs._body == "blah\nblah\nblah"


def test_resultsection_add_subsection():
    rs = ResultSection("title_text_as_str")

    # Add subsection
    ss1 = ResultSection("subsection")
    assert rs.add_subsection(ss1) is None
    assert rs.subsections == [ss1]
    assert ss1.parent == rs

    # Add subsection to bottom
    ss2 = ResultSection("subsection")
    assert rs.add_subsection(ss2) is None
    assert rs.subsections == [ss1, ss2]
    assert ss2.parent == rs

    # Add subsection to top
    ss3 = ResultSection("subsection")
    assert rs.add_subsection(ss3, on_top=True) is None
    assert rs.subsections == [ss3, ss1, ss2]
    assert ss3.parent == rs


def test_resultsection_add_tag():
    rs = ResultSection("title_text_as_str")

    # No tag type
    assert rs.add_tag("", "") is None
    assert rs._tags == {}

    # No empty string values allowed
    assert rs.add_tag("blah", "") is None
    assert rs._tags == {}

    # Standard
    assert rs.add_tag("blah", "blah") is None
    assert rs._tags == {"blah": ["blah"]}

    # Add the same value as before
    assert rs.add_tag("blah", "blah") is None
    assert rs._tags == {"blah": ["blah"]}

    # Add a different value
    assert rs.add_tag("blah", "blah1") is None
    assert rs._tags == {"blah": ["blah", "blah1"]}

    # Add an empty bytes value
    assert rs.add_tag("blah", b"") is None
    assert rs._tags == {"blah": ["blah", "blah1"]}

    # Add a bytes value
    assert rs.add_tag("blah", b"blah2") is None
    assert rs._tags == {"blah": ["blah", "blah1", "blah2"]}


def test_resultsection_finalize():
    rs = ResultSection("title_text_as_str")

    # Basic
    assert rs.finalize() is True
    assert rs._finalized is True
    assert rs.depth == 0
    assert rs._subsections == []

    # Call finalize again
    with pytest.raises(ResultAggregationException):
        rs.finalize()

    rs._finalized = False

    # Depth provided
    assert rs.finalize(1) is True
    assert rs.depth == 1

    rs._finalized = False

    # No title text
    rs.title_text = None
    assert rs.finalize() is False

    rs.title_text = "title_text_as_str"

    # Non-None body value
    rs._body = ""
    assert rs.finalize() is True
    assert rs._body is None

    rs._finalized = False

    # Subsections exist
    ss = ResultSection("blah")
    rs.add_subsection(ss)
    assert rs.finalize() is True
    assert rs.depth == 0
    assert ss.depth == 1

    rs._finalized = False
    ss._finalized = False

    # Subsections exist with depth provided
    ss = ResultSection("blah")
    rs.add_subsection(ss)
    assert rs.finalize(3) is True
    assert rs.depth == 3
    assert ss.depth == 4


def test_resultsection_set_body():
    rs = ResultSection("title_text_as_str")

    # body is str
    assert rs.set_body("") is None
    assert rs._body == ""
    assert rs._body_format == BODY_FORMAT.TEXT

    # passing body is str, body_format is provided
    assert rs.set_body("", BODY_FORMAT.GRAPH_DATA) is None
    assert rs._body == ""
    assert rs._body_format == BODY_FORMAT.GRAPH_DATA

    # body is a SectionBody, note that everything is overwritten
    assert rs.set_body(TextSectionBody("blah")) is None
    assert rs._body == "blah"
    assert rs._body_format == BODY_FORMAT.TEXT


def test_resultsection_set_heuristic():
    rs = ResultSection("title_text_as_str")

    # Pass None heuristic
    assert rs.set_heuristic(None) is None
    assert rs._heuristic is None

    # Pass int heuristic
    assert rs.set_heuristic(1) is None
    assert get_heuristic_primitives(rs._heuristic) == {'heur_id': 1, 'score': 250, 'attack_ids': [
        'T1005'], 'signatures': {}, 'frequency': 1, 'score_map': {}}

    rs._heuristic = None

    # Pass Heuristic heuristic
    heur = Heuristic(1)
    assert rs.set_heuristic(heur) is None
    assert get_heuristic_primitives(rs._heuristic) == {'heur_id': 1, 'score': 250, 'attack_ids': [
        'T1005'], 'signatures': {}, 'frequency': 1, 'score_map': {}}

    # Try adding a heuristic again
    with pytest.raises(InvalidHeuristicException):
        rs.set_heuristic(heur)

    rs._heuristic = None

    # Set the Heuristic heuristic with attack ID and signature
    heur = Heuristic(1)
    assert rs.set_heuristic(heur, attack_id="T1001", signature="blah") is None
    assert get_heuristic_primitives(
        rs._heuristic) == {
        'heur_id': 1, 'score': 250, 'attack_ids': ['T1005', 'T1001'],
        'signatures': {"blah": 1},
        'frequency': 1, 'score_map': {}}

    rs._heuristic = None

    # Set the int heuristic with attack ID and signature
    assert rs.set_heuristic(1, attack_id="T1001", signature="blah") is None
    assert get_heuristic_primitives(
        rs._heuristic) == {
        'heur_id': 1, 'score': 250, 'attack_ids': ['T1005', 'T1001'],
        'signatures': {"blah": 1},
        'frequency': 1, 'score_map': {}}


def test_resultsection_set_tags():
    rs = ResultSection("title_text_as_str")

    # Passing None as tags
    assert rs.set_tags(None) is None
    assert rs._tags == {}

    # Passing valid tags
    assert rs.set_tags({"a": "b"}) is None
    assert rs._tags == {"a": "b"}

    # Passing None as tags, note no overwrite
    assert rs.set_tags(None) is None
    assert rs._tags == {"a": "b"}

    # Passing empty dict as tags, note overwrite
    assert rs.set_tags({}) is None
    assert rs._tags == {}


def test_typespecificresultsection_init():
    sb = SectionBody(BODY_FORMAT.TEXT, "blah")
    # Pass the two kwargs that will be ignored
    tsrs = TypeSpecificResultSection("title_text_as_str", sb, body_format=BODY_FORMAT.GRAPH_DATA, body="blahblah")
    assert tsrs.section_body == sb
    assert tsrs.body_format == BODY_FORMAT.TEXT
    assert tsrs.body == "blah"


def test_typespecificresultsection_body():
    sb = SectionBody(BODY_FORMAT.TEXT, "blah")
    tsrs = TypeSpecificResultSection("title_text_as_str", sb)
    assert tsrs.body == "blah"


def test_typespecificresultsection_body_config():
    sb = SectionBody(BODY_FORMAT.TEXT, "blah")
    tsrs = TypeSpecificResultSection("title_text_as_str", sb)
    assert tsrs.body_config == {}


def test_typespecificresultsection_add_line():
    sb = SectionBody(BODY_FORMAT.TEXT, "blah")
    tsrs = TypeSpecificResultSection("title_text_as_str", sb)
    with pytest.raises(InvalidFunctionException):
        tsrs.add_line("blah")


def test_typespecificresultsection_add_lines():
    sb = SectionBody(BODY_FORMAT.TEXT, "blah")
    tsrs = TypeSpecificResultSection("title_text_as_str", sb)
    with pytest.raises(InvalidFunctionException):
        tsrs.add_lines("blah")


def test_typespecificresultsection_set_body():
    sb = SectionBody(BODY_FORMAT.TEXT, "blah")
    tsrs = TypeSpecificResultSection("title_text_as_str", sb)
    with pytest.raises(InvalidFunctionException):
        tsrs.set_body("blah")


def test_resulttextsection_init():
    rts = ResultTextSection("title_text_as_str")
    assert rts.body_format == BODY_FORMAT.TEXT


def test_resultmemorydumpsection_init():
    rmds = ResultMemoryDumpSection("title_text_as_str")
    assert rmds.body_format == BODY_FORMAT.MEMORY_DUMP


def test_resultgraphsection_init():
    rgx = ResultGraphSection("title_text_as_str")
    assert rgx.body_format == BODY_FORMAT.GRAPH_DATA


def test_resultgraphsection_set_colormap():
    rgs = ResultGraphSection("title_text_as_str", body_format=BODY_FORMAT.MEMORY_DUMP)
    assert rgs.set_colormap(0, 0, []) is None
    assert rgs.section_body._data == {"type": "colormap", "data": {"domain": [0, 0], "values": []}}
    assert rgs.body_format == BODY_FORMAT.GRAPH_DATA


def test_resulturlsection_init():
    rux = ResultURLSection("title_text_as_str")
    assert rux.body_format == BODY_FORMAT.URL


def test_resulturlsection_add_url():
    rux = ResultURLSection("title_text_as_str")

    # Name
    assert rux.add_url("blah", "blah") is None
    assert rux.section_body._data == [{"url": "blah", "name": "blah"}]


def test_resultkeyvaluesection_init():
    rkvs = ResultKeyValueSection("title_text_as_str")

    # No body
    assert rkvs.body_format == BODY_FORMAT.KEY_VALUE
    assert rkvs.section_body._data == {}

    # Some body as arg
    rkvs = ResultKeyValueSection("title_text_as_str", {"a": "b"})
    assert rkvs.section_body._data == {"a": "b"}

    # Some body as kwarg, note that this only works for the KVSectionBody
    with pytest.raises(TypeError):
        ResultKeyValueSection("title_text_as_str", a="b")


def test_resultkeyvaluesection_set_item():
    rkvs = ResultKeyValueSection("title_text_as_str")

    assert rkvs.set_item("a", "b") is None
    assert rkvs.section_body._data == {"a": "b"}


def test_resultkeyvaluesection_update_items():
    rkvs = ResultKeyValueSection("title_text_as_str")

    assert rkvs.update_items({"a": "b"}) is None
    assert rkvs.section_body._data == {"a": "b"}


def test_resultorderedkeyvaluesection_init():
    rokvs = ResultOrderedKeyValueSection("title_text_as_str")

    # No body
    assert rokvs.body_format == BODY_FORMAT.ORDERED_KEY_VALUE
    assert rokvs.section_body._data == []

    # Some body as arg
    rokvs = ResultOrderedKeyValueSection("title_text_as_str", {"a": "b"})
    assert rokvs.section_body._data == [("a", "b")]

    # Some body as kwarg, note that this only works for the OrderedKVSectionBody
    with pytest.raises(TypeError):
        ResultOrderedKeyValueSection("title_text_as_str", {}, a="b")


def test_resultorderedkeyvaluesection_add_item():
    rokvs = ResultOrderedKeyValueSection("title_text_as_str")

    assert rokvs.add_item(None, None) is None
    assert rokvs.section_body._data == [('None', None)]


def test_resultjsonsection_init():
    rjs = ResultJSONSection("title_text_as_str")

    # No body
    assert rjs.body_format == BODY_FORMAT.JSON
    assert rjs.section_body._data == {}


def test_resultjsonsection_set_json():
    rjs = ResultJSONSection("title_text_as_str")

    # No body
    assert rjs.set_json({}) is None
    assert rjs.section_body._data == {}

    # Some body
    assert rjs.set_json({"a": "b"}) is None
    assert rjs.section_body._data == {"a": "b"}

    # Override
    assert rjs.set_json({"b": "c"}) is None
    assert rjs.section_body._data == {"b": "c"}


def test_resultjsonsection_update_json():
    rjs = ResultJSONSection("title_text_as_str")

    # No body
    assert rjs.update_json({}) is None
    assert rjs.section_body._data == {}

    # Some body
    assert rjs.update_json({"a": "b"}) is None
    assert rjs.section_body._data == {"a": "b"}

    # Update
    assert rjs.update_json({"b": "c"}) is None
    assert rjs.section_body._data == {"a": "b", "b": "c"}


def test_resultprocesstreesection_init():
    rpts = ResultProcessTreeSection("title_text_as_str")

    assert rpts.body_format == BODY_FORMAT.PROCESS_TREE
    assert rpts.section_body._data == []


def test_resultprocesstreesection_add_process():
    rpts = ResultProcessTreeSection("title_text_as_str")

    pi = ProcessItem(123, "blah", "blah")
    assert rpts.add_process(pi) is None
    assert rpts.section_body._data == [
        {
            'children': [],
            'command_line': 'blah',
            'file_count': 0,
            'network_count': 0,
            'process_name': 'blah',
            'process_pid': 123,
            'registry_count': 0,
            'safelisted': False,
            'signatures': {}
        },
    ]


def test_resulttablesection_init():
    rts = ResultTableSection("title_text_as_str")

    assert rts.body_format == BODY_FORMAT.TABLE
    assert rts.section_body._data == []


def test_resulttablesection_add_row():
    rts = ResultTableSection("title_text_as_str")

    # Empty row
    tr = TableRow()
    assert rts.add_row(tr) is None
    assert rts.section_body._data == []
    assert rts.body_config == {}

    # Row with data
    tr = TableRow(a="b")
    assert rts.add_row(tr) is None
    assert rts.section_body._data == [{"a": "b"}]
    assert rts.body_config == {"column_order": ["a"]}

    # Overwrite column_order
    tr = TableRow(b="c", d="e")
    assert rts.add_row(tr) is None
    assert rts.section_body._data == [{"a": "b"}, {"b": "c", "d": "e"}]
    assert rts.body_config == {"column_order": ["b", "d"]}


def test_resulttablesection_set_column_order():
    rts = ResultTableSection("title_text_as_str")

    # Empty order
    assert rts.set_column_order([]) is None
    assert rts.body_config == {}

    # Some order
    assert rts.set_column_order(["a"]) is None
    assert rts.body_config == {"column_order": ["a"]}


def test_resultimagesection_init(service_request):
    ris = ResultImageSection(service_request, "title_text_as_str")

    assert ris.body_format == BODY_FORMAT.IMAGE
    assert ris.section_body._data == []
    assert ris.section_body._request == service_request


@pytest.mark.skipif(len(TESSERACT_LIST) < 1, reason="Requires tesseract-ocr apt package")
def test_resultimagesection_add_image(service_request):
    ris = ResultImageSection(service_request, "title_text_as_str")

    image_path = os.path.join(os.path.dirname(__file__),
                              "b32969aa664e3905c20f865cdd7b921f922678f5c3850c78e4c803fbc1757a8e")

    # Basic
    assert ris.add_image(image_path, "image_name", "description of image") is None
    assert ris.section_body._data == [{
        'img':
                                      {'name': 'image_name',
                                       'sha256': '09bf99ab5431af13b701a06dc2b04520aea9fd346584fa2a034d6d4af0c57329',
                                       'description': 'description of image'},
                                      'thumb':
                                      {'name': 'image_name.thumb',
                                       'sha256': '1af0e0d99845493b64cf402b3704170f17ecf15001714016e48f9d4854218901',
                                       'description': 'description of image (thumbnail)'}}]

    ris = ResultImageSection(service_request, "title_text_as_str")

    # Classification, OCR heuristic, OCR_IO, image with no password, auto_add_ocr_section is True
    ocr_heuristic_id = 1
    _, path = tempfile.mkstemp()
    ocr_io = open(path, "w")
    assert ris.add_image(image_path, "image_name", "description of image", "TLP:A", ocr_heuristic_id, ocr_io) is None
    assert ris.section_body._data == [{
        'img':
                                      {'name': 'image_name',
                                       'sha256': '09bf99ab5431af13b701a06dc2b04520aea9fd346584fa2a034d6d4af0c57329',
                                       'description': 'description of image'},
                                      'thumb':
                                      {'name': 'image_name.thumb',
                                       'sha256': '1af0e0d99845493b64cf402b3704170f17ecf15001714016e48f9d4854218901',
                                       'description': 'description of image (thumbnail)'}}]

    ris = ResultImageSection(service_request, "title_text_as_str")

    # Classification, OCR heuristic, OCR_IO, image with no password, auto_add_ocr_section is False
    ocr_heuristic_id = 1
    _, path = tempfile.mkstemp()
    ocr_io = open(path, "w")
    assert ris.add_image(image_path, "image_name", "description of image", "TLP:A", ocr_heuristic_id, ocr_io,
                         auto_add_ocr_section=False).body == '{"ransomware": ["YOUR FILES HAVE BEEN ENCRYPTED AND ' \
                                                             'YOU WON\'T BE ABLE TO DECRYPT THEM.", "YOU CAN BUY ' \
                                                             'DECRYPTION SOFTWARE FROM US, THIS SOFTWARE WILL ALLOW ' \
                                                             'YOU TO RECOVER ALL OF YOUR DATA AND", "RANSOMWARE FROM ' \
                                                             'YOUR COMPUTER. THE PRICE OF THE SOFTWARE IS $.2..%.. ' \
                                                             'PAYMENT CAN BE MADE IN BITCOIN OR XMR.", "How 00! PAY, ' \
                                                             'WHERE DO | GET BITCOIN OR XMR?", "YOURSELF TO FIND OUT ' \
                                                             'HOW TO BUY BITCOIN OR XMR.", "PAYMENT INFORMATION: ' \
                                                             'SEND $15, TO ONE OF OUR CRYPTO ADDRESSES, THEN SEND ' \
                                                             'US EMAIL WITH PAYMENT", "CONFIRMATION AND YOU\'LL GET ' \
                                                             'THE DECRYPTION SOFTWARE IN EMAIL.", "BTC ADDRESS : ' \
                                                             'bciqsht77cpgw7kv420r4secmu88g34wvn96dsyc5s"]}'
    assert ris.section_body._data == [{
        'img': {
            'name': 'image_name',
            'sha256': '09bf99ab5431af13b701a06dc2b04520aea9fd346584fa2a034d6d4af0c57329',
            'description': 'description of image'},
        'thumb': {
            'name': 'image_name.thumb',
            'sha256': '1af0e0d99845493b64cf402b3704170f17ecf15001714016e48f9d4854218901',
            'description': 'description of image (thumbnail)'}}]

    # Ensure that the image files added are marked as `is_image_section`
    image_hashes = [img['sha256'] for img in ris.section_body._data[0].values()]
    for file in service_request.task.supplementary:
        if file['is_section_image']:
            assert(file['sha256'] in image_hashes)


def test_resulttimelinesection_init():
    rts = ResultTimelineSection("title_text_as_str")

    assert rts.body_format == BODY_FORMAT.TIMELINE
    assert rts.section_body._data == []


def test_resulttimelinesection_add_node():
    rts = ResultTimelineSection("title_text_as_str")

    rts.add_node("title", "content", "opposite_content")
    assert rts.body_format == BODY_FORMAT.TIMELINE
    assert rts.section_body._data == [
        {'title': 'title', 'content': 'content',
         'opposite_content': 'opposite_content', 'icon': None, 'signatures': [], 'score': 0}]


def test_resultmultisection_init():
    rms = ResultMultiSection("title_text_as_str")

    assert rms.body_format == BODY_FORMAT.MULTI
    assert rms.section_body._data == []


def test_resultmultisection_add_section_part():
    rms = ResultMultiSection("title_text_as_str")

    rms.add_section_part(TextSectionBody("blah"))
    rms.add_section_part(GraphSectionBody())

    assert len(rms.section_body._data) == 2
    assert rms.section_body._data == [(BODY_FORMAT.TEXT, "blah", {}), (BODY_FORMAT.GRAPH_DATA, None, {})]


def test_result_init():
    # No sections
    r = Result()
    assert r._flattened_sections == []
    assert r._score == 0
    assert r.sections == []

    # Sections
    rs = ResultSection("blah")
    r = Result([rs])
    assert r._flattened_sections == []
    assert r._score == 0
    assert r.sections == [rs]


def test_result_append_section():
    r = Result()
    rs = ResultSection("blah")
    rs.set_heuristic(1)
    rs.set_tags({"blah.blah": ["blah"]})
    assert r._append_section(rs) is None
    assert len(r._flattened_sections) == 1


def test_result_flatten_sections():
    r = Result()
    rs = ResultSection("blah1")

    # root is True
    # Note, we have a single result section
    assert r._flatten_sections(rs) is None
    assert len(r._flattened_sections) == 1

    r._flattened_sections.clear()

    # Flatten ResultSection with subsection
    # Note, we have two result sections, the first is the parent, then second is the subsection
    ss1 = ResultSection("blah2")
    rs.add_subsection(ss1)
    assert r._flatten_sections(rs) is None
    assert len(r._flattened_sections) == 2

    # Flatten another ResultSection as not root. Because of this, we expect some weird behaviour
    # Note, we have four result sections. The first two are the same as above, expected. The next two
    # are the first subsection and the second subsection. This is because since "root=False", the
    # main result section is not added, only the subsections are.
    ss2 = ResultSection("blah3")
    rs.add_subsection(ss2)
    assert r._flatten_sections(rs, root=False) is None
    assert len(r._flattened_sections) == 4


def test_result_add_section():
    r = Result()

    # Add section
    rs1 = ResultSection("section")
    assert r.add_section(rs1) is None
    assert r.sections == [rs1]

    # Add section to bottom
    rs2 = ResultSection("section")
    assert r.add_section(rs2) is None
    assert r.sections == [rs1, rs2]

    # Add section to top
    rs3 = ResultSection("section")
    assert r.add_section(rs3, on_top=True) is None
    assert r.sections == [rs3, rs1, rs2]


def test_result_finalize():
    r = Result()

    # Default
    assert r.finalize() == {'score': 0, 'sections': []}

    # One section
    rs1 = ResultSection("section")
    r.add_section(rs1)
    assert r.sections == [rs1]
    finalized_r = r.finalize()
    assert finalized_r["score"] == 0
    assert len(finalized_r["sections"]) == 1
    assert r.sections == [rs1]

    rs1._finalized = False

    # Add a bad section
    rs2 = ResultSection("")
    r.add_section(rs2)
    assert r.sections == [rs1, rs2]

    # Note that the bad section is returned here, but does not exist in the sections param
    finalized_r = r.finalize()
    assert finalized_r["score"] == 0
    assert len(finalized_r["sections"]) == 2
    assert r.sections == [rs1]

    rs1._finalized = False
    r.sections.clear()
    r._flattened_sections.clear()
    r.add_section(rs1)

    # Add a section with a heuristic
    rs3 = ResultSection("section", heuristic=Heuristic(1))
    r.add_section(rs3)
    assert r.sections == [rs1, rs3]
    finalized_r = r.finalize()
    assert finalized_r["score"] == 250
    assert len(finalized_r["sections"]) == 2
    assert r.sections == [rs1, rs3]
