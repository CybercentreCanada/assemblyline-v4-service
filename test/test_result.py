import pytest
from assemblyline_v4_service.common.result import *


@pytest.fixture
def heuristic():
    return Heuristic(1)


@pytest.fixture
def sectionbody():
    return SectionBody("blah")


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

    # No line to add
    assert tsb.add_line(None) is None

    # Line to add
    assert tsb.add_line("blah") == "blah"

    # Line as list to add
    assert tsb.add_line(["blah", "blah"]) == "blah\nblahblah"


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
