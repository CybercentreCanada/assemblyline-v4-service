import pytest
import os

SERVICE_CONFIG_NAME = "service_manifest.yml"
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)


@pytest.fixture
def dummy_task_class():
    class DummyTask:
        def __init__(self):
            self.supplementary = []
            self.extracted = []
    yield DummyTask


@pytest.fixture
def dummy_event_class():
    class DummyEvent:
        def __init__(self, item):
            self.timestamp = item["timestamp"]
    yield DummyEvent


@pytest.fixture
def dummy_request_class(dummy_task_class):
    class DummyRequest(dict):
        def __init__(self):
            super(DummyRequest, self).__init__()
            self.task = dummy_task_class()

        def add_supplementary(self, path, name, description):
            self.task.supplementary.append({"path": path, "name": name, "description": description})

        def add_extracted(self, path, name, description):
            self.task.extracted.append({"path": path, "name": name, "description": description})

    yield DummyRequest


def check_artifact_equality(this, that):
    if this.name == that.name and this.path == that.path and this.description == that.description \
            and this.to_be_extracted == that.to_be_extracted:
        return True
    else:
        return False


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        heuristic_equality = this.heuristic.definition.attack_id == that.heuristic.definition.attack_id and \
                             this.heuristic.definition.classification == that.heuristic.definition.classification and \
                             this.heuristic.definition.description == that.heuristic.definition.description and \
                             this.heuristic.definition.filetype == that.heuristic.definition.filetype and \
                             this.heuristic.definition.heur_id == that.heuristic.definition.heur_id and \
                             this.heuristic.definition.id == that.heuristic.definition.id and \
                             this.heuristic.definition.max_score == that.heuristic.definition.max_score and \
                             this.heuristic.definition.name == that.heuristic.definition.name and \
                             this.heuristic.definition.score == that.heuristic.definition.score and \
                             this.heuristic.definition.signature_score_map == \
                             that.heuristic.definition.signature_score_map

        result_heuristic_equality = heuristic_equality and \
                                    this.heuristic.attack_ids == that.heuristic.attack_ids and \
                                    this.heuristic.frequency == that.heuristic.frequency and \
                                    this.heuristic.heur_id == that.heuristic.heur_id and \
                                    this.heuristic.score == that.heuristic.score and \
                                    this.heuristic.score_map == that.heuristic.score_map and \
                                    this.heuristic.signatures == that.heuristic.signatures

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = result_heuristic_equality and \
                               this.body == that.body and \
                               this.body_format == that.body_format and \
                               this.classification == that.classification and \
                               this.depth == that.depth and \
                               len(this.subsections) == len(that.subsections) and \
                               this.title_text == that.title_text

    if not current_section_equality:
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(subsection, that.subsections[index])
        if not subsection_equality:
            return False

    return True


def setup_module():
    if not os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        open_manifest = open(TEMP_SERVICE_CONFIG_PATH, "w")
        open_manifest.write("name: Sample\nversion: sample\ndocker_config: \n  image: sample\nheuristics:\n  - heur_id: 17\n    name: blah\n    description: blah\n    filetype: '*'\n    score: 250")


def teardown_module():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)


class TestEvent:
    @staticmethod
    @pytest.mark.parametrize("pid, image, timestamp, guid",
        [
            (None, None, None, None,),
            (1, 1, "blah", "blah",),
        ]
    )
    def test_init(pid, image, timestamp, guid):
        from assemblyline_v4_service.common.dynamic_service_helper import Event
        e = Event(pid, image, timestamp, guid)
        assert e.pid == pid
        assert e.image == image
        assert e.timestamp == timestamp
        assert e.guid == guid

    @staticmethod
    @pytest.mark.parametrize("pid, image, timestamp, guid, expected_result",
        [
            (None, None, None, None,
                {"image": None, "pid": None, "timestamp": None, "guid": None}),
            (1, "blah", 1.0, "blah",
                {"image": "blah", "pid": 1, "timestamp": 1.0, "guid": "blah"}),
        ]
    )
    def test_convert_event_to_dict(pid, image, timestamp, guid, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Event
        e = Event(pid=pid, image=image, timestamp=timestamp, guid=guid)
        actual_result = e.convert_event_to_dict()
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("path, expected_result",
        [
            ("blah", "x86"),
            ("C:\\program files\\blah", "x86"),
            ("C:\\program files (x86)\\blah", "x86_64"),
            ("C:\\syswow64\\blah", "x86_64"),
        ]
    )
    def test_determine_arch(path, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Event
        e = Event(pid=1, image=path, timestamp=0, guid="blah")
        actual_result = e._determine_arch(path)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("path, rule, expected_result",
        [
            ("blah", {"pattern": "", "replacement": ""}, "blah"),
            ("blah", {"pattern": "ah", "replacement": "ue"}, "blah"),
            ("blah", {"pattern": "bl", "replacement": "y"}, "yah"),
        ]
    )
    def test_pattern_substitution(path, rule, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Event
        e = Event(pid=1, image=path, timestamp=0, guid="blah")
        actual_result = e._pattern_substitution(path, rule)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("path, rule, expected_result",
         [
             ("blah", {"regex": "", "replacement": ""}, "blah"),
             ("blah", {"regex": "bl*ah", "replacement": "bl"}, "blah"),
             ("blah", {"regex": "\\bl*ah", "replacement": "bl"}, "blah"),
             ("blaah", {"regex": "bl*ah", "replacement": "blue"}, "blue"),
         ]
     )
    def test_regex_substitution(path, rule, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Event
        e = Event(pid=1, image=path, timestamp=0, guid="blah")
        actual_result = e._regex_substitution(path, rule)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("path, arch, expected_result",
        [
            ("blah", None, "blah"),
            ("C:\\Program Files\\Word.exe", None, "?pf86\\word.exe"),
            ("C:\\Program Files (x86)\\Word.exe", None, "?pf86\\word.exe"),
            ("C:\\Program Files (x86)\\Word.exe", "x86_64", "?pf86\\word.exe"),
            ("C:\\Windows\\System32\\Word.exe", None, "?sys32\\word.exe"),
            ("C:\\Windows\\SysWow64\\Word.exe", None, "?sys32\\word.exe"),
            ("C:\\Windows\\SysWow64\\Word.exe", "x86", "?win\\syswow64\\word.exe"),
            ("C:\\Windows\\SysWow64\\Word.exe", "x86_64", "?sys32\\word.exe"),
            ("C:\\Users\\buddy\\AppData\\Local\\Temp\\Word.exe", None, "?usrtmp\\word.exe"),
            ("C:\\Users\\buddy\\Word.exe", None, "?usr\\word.exe"),
        ]
    )
    def test_normalize_path(path, arch, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Event
        e = Event(pid=1, image=path, timestamp=0, guid="blah")
        actual_result = e._normalize_path(path, arch)
        assert actual_result == expected_result


class TestProcessEvent:
    @staticmethod
    @pytest.mark.parametrize("pid, ppid, image, command_line, timestamp",
        [
            (None, None, None, None, None),
            (1, 1, "blah", "blah", 1.0),
        ]
    )
    def test_init(pid, ppid, image, command_line, timestamp):
        from assemblyline_v4_service.common.dynamic_service_helper import ProcessEvent
        p = ProcessEvent(pid=pid, ppid=ppid, image=image, command_line=command_line, timestamp=timestamp)
        assert p.pid == pid
        assert p.ppid == ppid
        assert p.image == image
        assert p.command_line == command_line
        assert p.timestamp == timestamp


class TestNetworkEvent:
    @staticmethod
    @pytest.mark.parametrize("protocol, src_ip, src_port, domain, dest_ip, dest_port, pid, timestamp",
        [
            (None, None, None, None, None, None, None, None),
            ("blah", "blah", 1, "blah", "blah", 1, 1, 1.0),
        ]
    )
    def test_init(protocol, src_ip, src_port, domain, dest_ip, dest_port, pid, timestamp):
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkEvent
        n = NetworkEvent(protocol=protocol, src_ip=src_ip, src_port=src_port, domain=domain, dest_ip=dest_ip, dest_port=dest_port, pid=pid, timestamp=timestamp)
        assert n.protocol == protocol
        assert n.src_port == src_port
        assert n.domain == domain
        assert n.dest_ip == dest_ip
        assert n.dest_port == dest_port
        assert n.pid == pid
        assert n.timestamp == timestamp


class TestArtifact:
    @staticmethod
    @pytest.mark.parametrize("name, path, description, to_be_extracted",
        [
            (None, None, None, None),
            ("blah", "blah", "blah", True),
            ("blah", "blah", "blah", False),
        ]
    )
    def test_init(name, path, description, to_be_extracted):
        from assemblyline_v4_service.common.dynamic_service_helper import Artifact
        if any(item is None for item in [name, path, description, to_be_extracted]):
            with pytest.raises(Exception):
                Artifact(name=name, path=path, description=description, to_be_extracted=to_be_extracted)
            return
        a = Artifact(name=name, path=path, description=description, to_be_extracted=to_be_extracted)
        assert a.name == name
        assert a.path == path
        assert a.description == description
        assert a.to_be_extracted == to_be_extracted


class TestEvents:
    @staticmethod
    @pytest.mark.parametrize("events, expected_events, expected_sorted_events, expected_process_events, expected_network_events", [([], [], [], [], [])])
    def test_init(events, expected_events, expected_sorted_events, expected_process_events, expected_network_events):
        from assemblyline_v4_service.common.dynamic_service_helper import Events
        e = Events(events=events)
        assert e.events == expected_events
        assert e.sorted_events == expected_sorted_events
        assert e.process_events == expected_process_events
        assert e.network_events == expected_network_events

    @staticmethod
    @pytest.mark.parametrize("events, validated_events_num",
        [
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}], 1),
            ([{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}], 1),
            ([{}], 0),
        ]
    )
    def test_validate_events(events, validated_events_num):
        from assemblyline_v4_service.common.dynamic_service_helper import Events
        if validated_events_num:
            assert len(Events._validate_events(events)) == validated_events_num
        else:
            with pytest.raises(ValueError):
                Events._validate_events(events)

    @staticmethod
    @pytest.mark.parametrize("events, validated_events_num",
        [
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}], 1),
            ([{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}], 0),
        ]
    )
    def test_get_process_events(events, validated_events_num):
        from assemblyline_v4_service.common.dynamic_service_helper import Events
        validated_events = Events._validate_events(events)
        assert len(Events._get_process_events(validated_events)) == validated_events_num

    @staticmethod
    @pytest.mark.parametrize("events, validated_events_num",
        [
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}], 0),
            ([{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}], 1),
        ]
    )
    def test_get_network_events(events, validated_events_num):
        from assemblyline_v4_service.common.dynamic_service_helper import Events
        validated_events = Events._validate_events(events)
        assert len(Events._get_network_events(validated_events)) == validated_events_num

    @staticmethod
    @pytest.mark.parametrize("things_to_sort_by_timestamp, expected_result",
        [
            (None, []),
            ([], []),
            (
                    [{"timestamp": 1}],
                    [{"timestamp": 1}]
            ),
            (
                    [{"timestamp": 1}, {"timestamp": 2}],
                    [{"timestamp": 1}, {"timestamp": 2}]
            ),
            (
                    [{"timestamp": 1}, {"timestamp": 1}],
                    [{"timestamp": 1}, {"timestamp": 1}]
            ),
            (
                    [{"timestamp": 2}, {"timestamp": 1}],
                    [{"timestamp": 1}, {"timestamp": 2}]
            ),
            (
                    [{"timestamp": 3}, {"timestamp": 2}, {"timestamp": 1}],
                    [{"timestamp": 1}, {"timestamp": 2}, {"timestamp": 3}]
            ),
        ]
    )
    def test_sort_things_by_timestamp(things_to_sort_by_timestamp, expected_result, dummy_event_class):
        from assemblyline_v4_service.common.dynamic_service_helper import Events
        dummy_things = []
        dummy_results = []
        if things_to_sort_by_timestamp is None:
            assert Events._sort_things_by_timestamp(dummy_things) == []
            return
        for thing in things_to_sort_by_timestamp:
            dummy_things.append(dummy_event_class(thing))
        for result in expected_result:
            dummy_results.append(dummy_event_class(result))
        actual_result = Events._sort_things_by_timestamp(dummy_things)
        for index, item in enumerate(actual_result):
            assert item.__dict__ == dummy_results[index].__dict__

    @staticmethod
    @pytest.mark.parametrize("events, expected_events_dict",
        [
            ([{"pid": 1, "image": "blah", "timestamp": 1, "guid": None}], {1: {'guid': None, 'image': 'blah', 'pid': 1, 'timestamp': 1}}),
            ([{"pid": 1, "image": "blah", "timestamp": 1, "guid": None}, {"pid": 2, "image": "blah", "timestamp": 1, "guid": None}], {1: {'guid': None, 'image': 'blah', 'pid': 1, 'timestamp': 1}, 2: {'guid': None, 'image': 'blah', 'pid': 2, 'timestamp': 1}}),
            ([{"pid": 1, "image": "blah", "timestamp": 1, "guid": "a"}, {"pid": 2, "image": "blah", "timestamp": 1, "guid": "b"}], {"a": {'guid': "a", 'image': 'blah', 'pid': 1, 'timestamp': 1}, "b": {'guid': "b", 'image': 'blah', 'pid': 2, 'timestamp': 1}}),
        ]
    )
    def test_convert_events_to_dict(events, expected_events_dict):
        from assemblyline_v4_service.common.dynamic_service_helper import Event, Events
        event_objects = [Event(pid=event["pid"], image=event["image"], timestamp=event["timestamp"], guid=event["guid"]) for event in events]
        assert Events._convert_events_to_dict(event_objects) == expected_events_dict


class TestSandboxOntology:
    @staticmethod
    @pytest.mark.parametrize("events, expected_events", [([], [])])
    def test_init(events, expected_events):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so = SandboxOntology(events=events)
        assert so.events == expected_events

    @staticmethod
    @pytest.mark.parametrize("processes_dict, expected_result",
        [
            # No processes
            ({}, []),
            # One process
            (
                    {1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1}},
                    [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 1, "process_name": "blah", "children": []}]
            ),
            # One parent process and one child process
            (
                    {
                        1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1},
                        2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1},
                    },
                    [
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 1, "process_name": "blah",
                         "children":
                             [{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 2, "process_name": "blah", "children": []},]
                        },
                    ],
            ),
            # Two unrelated processes
            (
                    {
                        1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1},
                        2: {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1},
                    },
                    [
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 1, "process_name": "blah", "children": []},
                        {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 2, "process_name": "blah", "children": []},
                    ],
            ),
            # Three processes consisting of a parent-child relationship and a rando process
            (
                    {
                        1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1},
                        2: {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1},
                        3: {"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1},
                    },
                    [
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 1, "process_name": "blah", "children": []},
                        {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 2, "process_name": "blah",
                         "children":
                             [{"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 3, "process_name": "blah", "children": []}]
                         },
                    ],
            ),
            # Three processes consisting of a grandparent-parent-child relationship and one rando process
            (
                    {
                        1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1},
                        2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2},
                        3: {"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 3},
                        4: {"pid": 4, "ppid": 4, "image": "blah", "command_line": "blah", "timestamp": 2},
                    },
                    [
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 1, "process_name": "blah",
                         "children":
                            [{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2, "process_pid": 2, "process_name": "blah",
                              "children":
                                  [{"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 3, "process_pid": 3, "process_name": "blah",
                                    "children": []}, ]}]
                         },
                        {"pid": 4, "ppid": 4, "image": "blah", "command_line": "blah", "timestamp": 2, "process_pid": 4, "process_name": "blah", "children": []}
                    ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship
            (
                    {
                        1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1},
                        2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2},
                        3: {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3},
                        4: {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4},
                    },
                    [
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 1, "process_name": "blah",
                         "children":
                             [
                                 {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2, "process_pid": 2, "process_name": "blah",
                                  "children":
                                      [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4,  "process_pid": 4, "process_name": "blah", "children": []}]},
                                 {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3,  "process_pid": 3, "process_name": "blah", "children": []}
                              ]
                         },
                    ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship with non-ordered times
            (
                    {
                        1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1},
                        2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3},
                        3: {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2},
                        4: {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4},
                    },
                    [
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "process_pid": 1, "process_name": "blah",
                         "children":
                             [
                                 {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2, "process_pid": 3, "process_name": "blah",
                                  "children": []},
                                 {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3, "process_pid": 2, "process_name": "blah",
                                  "children":
                                      [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4, "process_pid": 4, "process_name": "blah",
                                        "children": []}]},
                             ]
                         },
                    ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship with non-ordered times using guids
            (
                    {
                        "a": {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a", "pguid": None},
                        "b": {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3, "guid": "b", "pguid": "a"},
                        "c": {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2, "guid": "c", "pguid": "a"},
                        "d": {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4, "guid": "d", "pguid": "b"},
                    },
                    [
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a", "pguid": None, "process_pid": 1, "process_name": "blah",
                         "children":
                             [
                                 {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2, "guid": "c", "pguid": "a", "process_pid": 3, "process_name": "blah",
                                  "children": []},
                                 {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3, "guid": "b", "pguid": "a", "process_pid": 2, "process_name": "blah",
                                  "children":
                                      [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4, "guid": "d", "pguid": "b", "process_pid": 4, "process_name": "blah",
                                        "children": []}]},
                             ]
                         },
                    ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship with non-ordered times using guids
            (
                    {
                        1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None,
                              "pguid": None},
                        2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3, "guid": None,
                              "pguid": None},
                        3: {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2, "guid": None,
                              "pguid": None},
                        4: {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4, "guid": None,
                              "pguid": None},
                    },
                    [
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None,
                         "pguid": None, "process_pid": 1, "process_name": "blah",
                         "children":
                             [
                                 {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2,
                                  "guid": None, "pguid": None, "process_pid": 3, "process_name": "blah",
                                  "children": []},
                                 {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3,
                                  "guid": None, "pguid": None, "process_pid": 2, "process_name": "blah",
                                  "children":
                                      [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4,
                                        "guid": None, "pguid": None, "process_pid": 4, "process_name": "blah",
                                        "children": []}]},
                             ]
                         },
                    ],
            ),
        ]
    )
    def test_convert_processes_dict_to_tree(processes_dict, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        actual_result = SandboxOntology._convert_processes_dict_to_tree(processes_dict)
        assert expected_result == actual_result

    @staticmethod
    @pytest.mark.parametrize("artifact_list",
        [
            None,
            [],
            [{"name": "blah", "path": "blah", "description": "blah", "to_be_extracted": True}],
        ]
    )
    def test_validate_artifacts(artifact_list):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Artifact
        actual_validated_artifact_list = SandboxOntology._validate_artifacts(artifact_list)
        if artifact_list is None:
            artifact_list = []
        for index, artifact in enumerate(artifact_list):
            expected_artifact = Artifact(
                name=artifact["name"],
                path=artifact["path"],
                description=artifact["description"],
                to_be_extracted=artifact["to_be_extracted"]
            )
            assert check_artifact_equality(expected_artifact, actual_validated_artifact_list[index])

    @staticmethod
    @pytest.mark.parametrize("artifact, expected_result_section_title",
        [
            (None, None),
            ({"path": "blah", "name": "blah", "description": "blah", "to_be_extracted": True}, None),
            ({"path": "blah", "name": "123_hollowshunter/hh_process_123_blah.exe", "description": "blah", "to_be_extracted": True}, "HollowsHunter Injected Portable Executable"),
            ({"path": "blah", "name": "123_hollowshunter/hh_process_123_blah.shc", "description": "blah", "to_be_extracted": True}, None),
            ({"path": "blah", "name": "123_hollowshunter/hh_process_123_blah.dll", "description": "blah", "to_be_extracted": True}, "HollowsHunter DLL"),
        ]
    )
    def test_handle_artifact(artifact, expected_result_section_title):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Artifact
        from assemblyline_v4_service.common.result import ResultSection, Heuristic

        if artifact is None:
            with pytest.raises(Exception):
                SandboxOntology._handle_artifact(artifact, None)
            return

        expected_result_section = None
        if expected_result_section_title is not None:
            expected_result_section = ResultSection(expected_result_section_title)
            expected_result_section.add_tag("dynamic.process.file_name", artifact["path"])
            if expected_result_section_title == "HollowsHunter Injected Portable Executable":
                heur = Heuristic(17)
                heur.add_signature_id("hollowshunter_pe")
                expected_result_section.heuristic = heur
        parent_result_section = ResultSection("blah")
        a = Artifact(
            name=artifact["name"],
            path=artifact["path"],
            description=artifact["description"],
            to_be_extracted=artifact["to_be_extracted"]
        )
        SandboxOntology._handle_artifact(a, parent_result_section)
        if len(parent_result_section.subsections) > 0:
            actual_result_section = parent_result_section.subsections[0]
        else:
            actual_result_section = None

        if expected_result_section is None and actual_result_section is None:
            assert True
        else:
            assert check_section_equality(actual_result_section, expected_result_section)

    @staticmethod
    @pytest.mark.parametrize("process_list, signatures, expected_result",
        [
            (None, [], {}),
            ([], [], {}),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None}], [{"pid": 1, "name": "blah", "score": 1}], {1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None, "signatures": {"blah": 1}}}),
            ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None}], [{"pid": 1, "name": "blah", "score": 1}], {2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None, "signatures": {}}}),
            ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a", "pguid": None}], [{"pid": 1, "name": "blah", "score": 1}], {"a": {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a", "pguid": None, "signatures": {}}}),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a", "pguid": None}], [{"pid": 1, "name": "blah", "score": 1}], {"a": {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a", "pguid": None, "signatures": {"blah": 1}}}),
        ]
    )
    def test_match_signatures_to_process_events(process_list, signatures, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        o = SandboxOntology(process_list)
        actual_result = o._match_signatures_to_process_events(signature_dicts=signatures)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("process_list, safelist, expected_result", 
        [
            (None, [], []), 
            ([], [], []),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "pguid": "blahblah"}], [], [{'pid': 1, 'image': 'blah', 'timestamp': 1, 'guid': 'blah', 'ppid': 1, 'pguid': 'blahblah', 'command_line': 'blah', 'process_pid': 1, 'process_name': 'blah', 'children': []}]),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "pguid": "blahblah"}, {"pid": 2, "ppid": 1, "image": "blah2", "command_line": "blah2", "timestamp": 2, "guid": "blah2", "pguid": "blah"}], [], [{'pid': 1, 'image': 'blah', 'timestamp': 1, 'guid': 'blah', 'ppid': 1, 'pguid': 'blahblah', 'command_line': 'blah', 'process_pid': 1, 'process_name': 'blah', 'children': [{'pid': 2, 'image': 'blah2', 'timestamp': 2, 'guid': 'blah2', 'ppid': 1, 'pguid': 'blah', 'command_line': 'blah2', 'process_pid': 2, 'process_name': 'blah2', 'children': []}]}]),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "pguid": "blahblah"}, {"pid": 2, "ppid": 1, "image": "blah2", "command_line": "blah2", "timestamp": 2, "guid": "blah2", "pguid": "blah"}, {"pid": 3, "ppid": 3, "image": "blah3", "command_line": "blah3", "timestamp": 1, "guid": "blah3", "pguid": "blah3"}, {"pid": 4, "ppid": 3, "image": "blah4", "command_line": "blah4", "timestamp": 2, "guid": "blah4", "pguid": "blah3"} ], [], [ {'pid': 1, 'image': 'blah', 'timestamp': 1, 'guid': 'blah', 'ppid': 1, 'pguid': 'blahblah', 'command_line': 'blah', 'process_pid': 1, 'process_name': 'blah', 'children': [ {'pid': 2, 'image': 'blah2', 'timestamp': 2, 'guid': 'blah2', 'ppid': 1, 'pguid': 'blah', 'command_line': 'blah2', 'process_pid': 2, 'process_name': 'blah2', 'children': [] } ] }, {'pid': 3, 'image': 'blah3', 'timestamp': 1, 'guid': 'blah3', 'ppid': 3, 'pguid': 'blah3', 'command_line': 'blah3', 'process_pid': 3, 'process_name': 'blah3', 'children': [ {'pid': 4, 'image': 'blah4', 'timestamp': 2, 'guid': 'blah4', 'ppid': 3, 'pguid': 'blah3', 'command_line': 'blah4', 'process_pid': 4, 'process_name': 'blah4', 'children': [] } ] } ] ),
            ([{"pid": 0, "image": "?pf86\\microsoft office\\office14\\excel.exe", "timestamp": 1631203119.713387, "guid": "excel", "pguid": "excel", "ppid": 0, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", }, { "pid": 1, "image": "?sys32\\wbem\\wmic1.exe", "timestamp": 1631203128.413, "guid": "wmic1", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 11, "image": "?sys32\\wbem\\wmic11.exe", "timestamp": 1631203138.413, "guid": "wmic11", "pguid": "wmic1", "ppid": 1, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 111, "image": "?sys32\\wbem\\wmic111.exe", "timestamp": 1631303128.413, "guid": "wmic111", "pguid": "wmic11", "ppid": 11, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 12, "image": "?sys32\\wbem\\wmic12.exe", "timestamp": 1631203148.413, "guid": "wmic12", "pguid": "wmic1", "ppid": 1, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 2, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "guid": "wmic2", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 3, "image": "?sys32\\wbem\\wmic3.exe", "timestamp": 1633203128.413, "guid": "wmic3", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 31, "image": "?sys32\\wbem\\wmic31.exe", "timestamp": 1634203128.413, "guid": "wmic31", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 32, "image": "?sys32\\wbem\\wmic32.exe", "timestamp": 1635203128.413, "guid": "wmic32", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 33, "image": "?sys32\\wbem\\wmic33.exe", "timestamp": 1636203128.413, "guid": "wmic33", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", } ], [], [ { "pid": 0, "image": "?pf86\\microsoft office\\office14\\excel.exe", "timestamp": 1631203119.713387, "guid": "excel", "ppid": 0, "pguid": "excel", "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", "process_pid": 0, "process_name": "?pf86\\microsoft office\\office14\\excel.exe", "children": [ { "pid": 1, "image": "?sys32\\wbem\\wmic1.exe", "timestamp": 1631203128.413, "guid": "wmic1", "ppid": 0, "pguid": "excel", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 1, "process_name": "?sys32\\wbem\\wmic1.exe", "children": [ { "pid": 11, "image": "?sys32\\wbem\\wmic11.exe", "timestamp": 1631203138.413, "guid": "wmic11", "ppid": 1, "pguid": "wmic1", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 11, "process_name": "?sys32\\wbem\\wmic11.exe", "children": [ { "pid": 111, "image": "?sys32\\wbem\\wmic111.exe", "timestamp": 1631303128.413, "guid": "wmic111", "ppid": 11, "pguid": "wmic11", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 111, "process_name": "?sys32\\wbem\\wmic111.exe", "children": []}]}, { "pid": 12, "image": "?sys32\\wbem\\wmic12.exe", "timestamp": 1631203148.413, "guid": "wmic12", "ppid": 1, "pguid": "wmic1", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 12, "process_name": "?sys32\\wbem\\wmic12.exe", "children": []}]}, { "pid": 2, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "guid": "wmic2", "ppid": 0, "pguid": "excel", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 2, "process_name": "?sys32\\wbem\\wmic2.exe", "children": []}, { "pid": 3, "image": "?sys32\\wbem\\wmic3.exe", "timestamp": 1633203128.413, "guid": "wmic3", "ppid": 0, "pguid": "excel", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 3, "process_name": "?sys32\\wbem\\wmic3.exe", "children": [ { "pid": 31, "image": "?sys32\\wbem\\wmic31.exe", "timestamp": 1634203128.413, "guid": "wmic31", "ppid": 3, "pguid": "wmic3", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 31, "process_name": "?sys32\\wbem\\wmic31.exe", "children": []}, { "pid": 32, "image": "?sys32\\wbem\\wmic32.exe", "timestamp": 1635203128.413, "guid": "wmic32", "ppid": 3, "pguid": "wmic3", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 32, "process_name": "?sys32\\wbem\\wmic32.exe", "children": []}, { "pid": 33, "image": "?sys32\\wbem\\wmic33.exe", "timestamp": 1636203128.413, "guid": "wmic33", "ppid": 3, "pguid": "wmic3", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 33, "process_name": "?sys32\\wbem\\wmic33.exe", "children": [] } ] } ] } ] ),
            ([{"pid": 0, "image": "?pf86\\microsoft office\\office14\\excel.exe", "timestamp": 1631203119.713387, "guid": "excel", "pguid": "excel", "ppid": 0, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", }, { "pid": 1, "image": "?sys32\\wbem\\wmic1.exe", "timestamp": 1631203128.413, "guid": "wmic1", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 11, "image": "?sys32\\wbem\\wmic11.exe", "timestamp": 1631203138.413, "guid": "wmic11", "pguid": "wmic1", "ppid": 1, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 111, "image": "?sys32\\wbem\\wmic111.exe", "timestamp": 1631303128.413, "guid": "wmic111", "pguid": "wmic11", "ppid": 11, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 12, "image": "?sys32\\wbem\\wmic12.exe", "timestamp": 1631203148.413, "guid": "wmic12", "pguid": "wmic1", "ppid": 1, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 2, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "guid": "wmic2", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 3, "image": "?sys32\\wbem\\wmic3.exe", "timestamp": 1633203128.413, "guid": "wmic3", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 31, "image": "?sys32\\wbem\\wmic31.exe", "timestamp": 1634203128.413, "guid": "wmic31", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 32, "image": "?sys32\\wbem\\wmic32.exe", "timestamp": 1635203128.413, "guid": "wmic32", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 33, "image": "?sys32\\wbem\\wmic33.exe", "timestamp": 1636203128.413, "guid": "wmic33", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", } ], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac'], [ { "pid": 0, "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "timestamp": 1631203119.713387, "guid": "excel", "ppid": 0, "pguid": "excel", "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", "process_pid": 0, "process_name": "?pf86\\microsoft office\\office14\\excel.exe", "children": [ { "pid": 1, "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "timestamp": 1631203128.413, "guid": "wmic1", "ppid": 0, "pguid": "excel", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 1, "process_name": "?sys32\\wbem\\wmic1.exe", "children": [ { "pid": 12, "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "timestamp": 1631203148.413, "guid": "wmic12", "ppid": 1, "pguid": "wmic1", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 12, "process_name": "?sys32\\wbem\\wmic12.exe", "children": [] } ] }, { "pid": 2, "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "timestamp": 1632203128.413, "guid": "wmic2", "ppid": 0, "pguid": "excel", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 2, "process_name": "?sys32\\wbem\\wmic2.exe", "children": []}, { "pid": 3, "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "timestamp": 1633203128.413, "guid": "wmic3", "ppid": 0, "pguid": "excel", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 3, "process_name": "?sys32\\wbem\\wmic3.exe", "children": [ { "pid": 31, "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "timestamp": 1634203128.413, "guid": "wmic31", "ppid": 3, "pguid": "wmic3", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 31, "process_name": "?sys32\\wbem\\wmic31.exe", "children": []}, { "pid": 32, "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "timestamp": 1635203128.413, "guid": "wmic32", "ppid": 3, "pguid": "wmic3", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 32, "process_name": "?sys32\\wbem\\wmic32.exe", "children": []}, { "pid": 33, "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "timestamp": 1636203128.413, "guid": "wmic33", "ppid": 3, "pguid": "wmic3", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 33, "process_name": "?sys32\\wbem\\wmic33.exe", "children": [] } ] } ] } ] ),
            ([{"pid": 0, "image": "?pf86\\microsoft office\\office14\\excel.exe", "timestamp": 1631203119.713387, "guid": "excel", "pguid": "excel", "ppid": 0, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", }, { "pid": 1, "image": "?sys32\\wbem\\wmic1.exe", "timestamp": 1631203128.413, "guid": "wmic1", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 11, "image": "?sys32\\wbem\\wmic11.exe", "timestamp": 1631203138.413, "guid": "wmic11", "pguid": "wmic1", "ppid": 1, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 111, "image": "?sys32\\wbem\\wmic111.exe", "timestamp": 1631303128.413, "guid": "wmic111", "pguid": "wmic11", "ppid": 11, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 12, "image": "?sys32\\wbem\\wmic12.exe", "timestamp": 1631203148.413, "guid": "wmic12", "pguid": "wmic1", "ppid": 1, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 2, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "guid": "wmic2", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 3, "image": "?sys32\\wbem\\wmic3.exe", "timestamp": 1633203128.413, "guid": "wmic3", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 31, "image": "?sys32\\wbem\\wmic31.exe", "timestamp": 1634203128.413, "guid": "wmic31", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 32, "image": "?sys32\\wbem\\wmic32.exe", "timestamp": 1635203128.413, "guid": "wmic32", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 33, "image": "?sys32\\wbem\\wmic33.exe", "timestamp": 1636203128.413, "guid": "wmic33", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", } ], ['6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], [ { "pid": 0, "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "timestamp": 1631203119.713387, "guid": "excel", "ppid": 0, "pguid": "excel", "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", "process_pid": 0, "process_name": "?pf86\\microsoft office\\office14\\excel.exe", "children": [ { "pid": 1, "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "timestamp": 1631203128.413, "guid": "wmic1", "ppid": 0, "pguid": "excel", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 1, "process_name": "?sys32\\wbem\\wmic1.exe", "children": [ { "pid": 11, "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "timestamp": 1631203138.413, "guid": "wmic11", "ppid": 1, "pguid": "wmic1", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 11, "process_name": "?sys32\\wbem\\wmic11.exe", "children": [ { "pid": 111, "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "timestamp": 1631303128.413, "guid": "wmic111", "ppid": 11, "pguid": "wmic11", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 111, "process_name": "?sys32\\wbem\\wmic111.exe", "children": []}]}, { "pid": 12, "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "timestamp": 1631203148.413, "guid": "wmic12", "ppid": 1, "pguid": "wmic1", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 12, "process_name": "?sys32\\wbem\\wmic12.exe", "children": []}]}, { "pid": 2, "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "timestamp": 1632203128.413, "guid": "wmic2", "ppid": 0, "pguid": "excel", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 2, "process_name": "?sys32\\wbem\\wmic2.exe", "children": []}, ] } ] ),
            ([{"pid": 0, "image": "?pf86\\microsoft office\\office14\\excel.exe", "timestamp": 1631203119.713387, "guid": "excel", "pguid": "excel", "ppid": 0, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", }, { "pid": 1, "image": "?sys32\\wbem\\wmic1.exe", "timestamp": 1631203128.413, "guid": "wmic1", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 11, "image": "?sys32\\wbem\\wmic11.exe", "timestamp": 1631203138.413, "guid": "wmic11", "pguid": "wmic1", "ppid": 1, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 111, "image": "?sys32\\wbem\\wmic111.exe", "timestamp": 1631303128.413, "guid": "wmic111", "pguid": "wmic11", "ppid": 11, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 12, "image": "?sys32\\wbem\\wmic12.exe", "timestamp": 1631203148.413, "guid": "wmic12", "pguid": "wmic1", "ppid": 1, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 2, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "guid": "wmic2", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 3, "image": "?sys32\\wbem\\wmic3.exe", "timestamp": 1633203128.413, "guid": "wmic3", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 31, "image": "?sys32\\wbem\\wmic31.exe", "timestamp": 1634203128.413, "guid": "wmic31", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 32, "image": "?sys32\\wbem\\wmic32.exe", "timestamp": 1635203128.413, "guid": "wmic32", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 33, "image": "?sys32\\wbem\\wmic33.exe", "timestamp": 1636203128.413, "guid": "wmic33", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", } ], ['6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b'], [ { "pid": 0, "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "timestamp": 1631203119.713387, "guid": "excel", "ppid": 0, "pguid": "excel", "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", "process_pid": 0, "process_name": "?pf86\\microsoft office\\office14\\excel.exe", "children": [ { "pid": 1, "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "timestamp": 1631203128.413, "guid": "wmic1", "ppid": 0, "pguid": "excel", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 1, "process_name": "?sys32\\wbem\\wmic1.exe", "children": [ { "pid": 11, "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "timestamp": 1631203138.413, "guid": "wmic11", "ppid": 1, "pguid": "wmic1", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 11, "process_name": "?sys32\\wbem\\wmic11.exe", "children": [ { "pid": 111, "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "timestamp": 1631303128.413, "guid": "wmic111", "ppid": 11, "pguid": "wmic11", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 111, "process_name": "?sys32\\wbem\\wmic111.exe", "children": []}]}, ] }, { "pid": 3, "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "timestamp": 1633203128.413, "guid": "wmic3", "ppid": 0, "pguid": "excel", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 3, "process_name": "?sys32\\wbem\\wmic3.exe", "children": [ { "pid": 31, "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "timestamp": 1634203128.413, "guid": "wmic31", "ppid": 3, "pguid": "wmic3", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 31, "process_name": "?sys32\\wbem\\wmic31.exe", "children": []}, { "pid": 32, "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "timestamp": 1635203128.413, "guid": "wmic32", "ppid": 3, "pguid": "wmic3", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 32, "process_name": "?sys32\\wbem\\wmic32.exe", "children": []}, { "pid": 33, "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "timestamp": 1636203128.413, "guid": "wmic33", "ppid": 3, "pguid": "wmic3", "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "process_pid": 33, "process_name": "?sys32\\wbem\\wmic33.exe", "children": [] } ] } ] } ] ),
            ([{"pid": 0, "image": "?pf86\\microsoft office\\office14\\excel.exe", "timestamp": 1631203119.713387, "guid": "excel", "pguid": "excel", "ppid": 0, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", }, { "pid": 1, "image": "?sys32\\wbem\\wmic1.exe", "timestamp": 1631203128.413, "guid": "wmic1", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 11, "image": "?sys32\\wbem\\wmic11.exe", "timestamp": 1631203138.413, "guid": "wmic11", "pguid": "wmic1", "ppid": 1, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 111, "image": "?sys32\\wbem\\wmic111.exe", "timestamp": 1631303128.413, "guid": "wmic111", "pguid": "wmic11", "ppid": 11, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 12, "image": "?sys32\\wbem\\wmic12.exe", "timestamp": 1631203148.413, "guid": "wmic12", "pguid": "wmic1", "ppid": 1, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 2, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "guid": "wmic2", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 3, "image": "?sys32\\wbem\\wmic3.exe", "timestamp": 1633203128.413, "guid": "wmic3", "pguid": "excel", "ppid": 0, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 31, "image": "?sys32\\wbem\\wmic31.exe", "timestamp": 1634203128.413, "guid": "wmic31", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 32, "image": "?sys32\\wbem\\wmic32.exe", "timestamp": 1635203128.413, "guid": "wmic32", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", }, { "pid": 33, "image": "?sys32\\wbem\\wmic33.exe", "timestamp": 1636203128.413, "guid": "wmic33", "pguid": "wmic3", "ppid": 3, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", } ], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], [ ] )
        ]
    )
    def test_get_process_tree(process_list, safelist, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        o = SandboxOntology(process_list)
        actual_result = o.get_process_tree(safelist)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("process_list, signatures, expected_result",
        [
            (None, [], []),
            ([], [], []),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "pguid": "blahblah"}], [{"pid": 1, "name": "blah", "score": 1}], [{"children": [], "pid": 1, "ppid": 1, "process_name": "blah", "process_pid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "pguid": "blahblah", "signatures": {"blah": 1}}]),
            ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "pguid": "blahblah"}], [{"pid": 1, "name": "blah", "score": 1}], [{"children": [], "pid": 2, "ppid": 1, "process_name": "blah", "process_pid": 2, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "pguid": "blahblah", "signatures": {}}]),
        ]
    )
    def test_get_process_tree_with_signatures(process_list, signatures, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        o = SandboxOntology(process_list)
        actual_result = o.get_process_tree_with_signatures(signatures=signatures)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "parent, node, expected_node, expected_hashes",
        [
            ("",
             {"image": "blah", "children": []},
             {
                 'children': [],
                 'image': 'blah',
                 'node_hash': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52'
             },
             ['8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52']
            ),
            ("8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52",
             {"image": "blah", "children": []},
             {
                 'children': [],
                 'image': 'blah',
                 'node_hash': '36e7b71783ff1cd0f9ea9b953f3e711536fcde580c8e74b6cba4e6798064bc8e'
             },
             ['36e7b71783ff1cd0f9ea9b953f3e711536fcde580c8e74b6cba4e6798064bc8e']
            ),
            ("",
             {
                 "image": "got the image",
                  "children": [
                      {"image": "image number 2", "children": []},
                      {"image": "image number 3", "children": []}
                  ]
             },
             {
                 "image": "got the image",
                 "node_hash": "b71bf6eacf36ecdf07b3f1efa5d6f50725271ca85369b966e19da5b76c175b5b",
                 "children": [
                     {"image": "image number 2", "node_hash": "294156e02fb77c860933c93da8629dbceab367629a1ff9af68ff4b03c8596b17", "children": []},
                     {"image": "image number 3", "node_hash": "0483e740e929697527964c71227dd76403cdc91ca16e7a4a9a430f734481f129", "children": []}
                 ]
             },
             ['294156e02fb77c860933c93da8629dbceab367629a1ff9af68ff4b03c8596b17',
              '0483e740e929697527964c71227dd76403cdc91ca16e7a4a9a430f734481f129']
            ),

        ]
    )
    def test_create_hashed_node(parent, node, expected_node, expected_hashes):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        hashes = []
        SandboxOntology._create_hashed_node(parent, node, hashes)
        assert hashes == expected_hashes
        assert node == expected_node

    @staticmethod
    @pytest.mark.parametrize(
        "process_tree, expected_process_tree, expected_process_tree_hashes",
        [
            (
                [
                    {
                        "image": "?pf86\\microsoft office\\office14\\excel.exe",
                        "children":
                            [
                                {
                                    "image": "?sys32\\wbem\\wmic1.exe",
                                    "children":
                                        [
                                            {
                                                "image": "?sys32\\wbem\\wmic11.exe",
                                                "children":
                                                    [
                                                        {
                                                            "image": "?sys32\\wbem\\wmic111.exe",
                                                            "children": []
                                                        }
                                                    ]
                                            },
                                            {
                                                "image": "?sys32\\wbem\\wmic12.exe",
                                                "children": []
                                            }
                                        ]
                                },
                                {
                                    "image": "?sys32\\wbem\\wmic2.exe",
                                    "children": []
                                },
                                {
                                    "image": "?sys32\\wbem\\wmic3.exe",
                                    "children":
                                        [
                                            {
                                                "image": "?sys32\\wbem\\wmic31.exe",
                                                "children": []
                                            },
                                            {
                                                "image": "?sys32\\wbem\\wmic32.exe",
                                                "children": []
                                            },
                                            {
                                                "image": "?sys32\\wbem\\wmic33.exe",
                                                "children": []
                                            }
                                        ]
                                }
                            ]
                    }
                ],
                [
                    {
                        "image": "?pf86\\microsoft office\\office14\\excel.exe",
                        "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62",
                        "children":
                            [
                                {
                                    "image": "?sys32\\wbem\\wmic1.exe",
                                    "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448",
                                    "children":
                                        [
                                            {
                                                "image": "?sys32\\wbem\\wmic11.exe",
                                                "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464",
                                                "children":
                                                    [
                                                        {
                                                             "image": "?sys32\\wbem\\wmic111.exe",
                                                             "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac",
                                                             "children": []
                                                        }
                                                    ]
                                            },
                                            {
                                                "image": "?sys32\\wbem\\wmic12.exe",
                                                "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d",
                                                "children": []
                                            }
                                        ]
                                },
                                {
                                    "image": "?sys32\\wbem\\wmic2.exe",
                                    "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b",
                                    "children": []
                                },
                                {
                                    "image": "?sys32\\wbem\\wmic3.exe",
                                    "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7",
                                    "children":
                                        [
                                            {
                                                "image": "?sys32\\wbem\\wmic31.exe",
                                                "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40",
                                                "children": []
                                            },
                                            {
                                                "image": "?sys32\\wbem\\wmic32.exe",
                                                "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd",
                                                "children": []
                                            },
                                            {
                                                "image": "?sys32\\wbem\\wmic33.exe",
                                                "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5",
                                                "children": []
                                            }
                                        ]
                                }
                            ]
                    }
                ],
                [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac',
                 '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d',
                 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b',
                 '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40',
                 '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd',
                 '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']]),
        ]
    )
    def test_create_hashes(process_tree, expected_process_tree, expected_process_tree_hashes):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        hashes = SandboxOntology._create_hashes(process_tree)
        assert hashes == expected_process_tree_hashes
        assert process_tree == expected_process_tree

    @staticmethod
    @pytest.mark.parametrize(
        'process_tree, expected_leaf_hashes',
        [ 
            ([{ "pid": 7100, "image": "C:\\Program Files (x86)\\Microsoft Office\\Office14\\EXCEL.EXE", "timestamp": 1631903280.208475, "guid": "placeholder", "ppid": 2528, "command_line": "\"C:\\Program Files (x86)\\Microsoft Office\\Office14\\EXCEL.EXE\" C:\\Users\\buddy\\AppData\\Local\\Temp\\3617524f469002f54459d47e97fe757661b4e7a776b04cbfab50e746d779a31c.xls", "signatures": { "stealth_window": 100, "injection_resumethread": 250 }, "process_pid": 7100, "process_name": "C:\\Program Files (x86)\\Microsoft Office\\Office14\\EXCEL.EXE", "children": [ { "pid": 5036, "image": "C:\\Windows\\SysWOW64\\cmd.exe", "timestamp": 1631903284.061, "guid": "{4e46ad60-de34-6144-d803-000000000c00}", "ppid": 7100, "command_line": "\"C:\\Windows\\System32\\cmd.exe\" /C PO^W^ers^HE^lL -E somebase64=", "signatures": { "injection_resumethread": 250 }, "process_pid": 5036, "process_name": "C:\\Windows\\SysWOW64\\cmd.exe", "children": [ { "pid": 4796, "image": "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe", "timestamp": 1631903284.377, "guid": "{4e46ad60-de34-6144-dc03-000000000c00}", "ppid": 5036, "command_line": "POWersHElL  -E somebase64=", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "privilege_luid_check": 100, "injection_resumethread": 250 }, "process_pid": 4796, "process_name": "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe", "children": [ { "pid": 4832, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\ipa.exe", "timestamp": 1631903312.724, "guid": "{4e46ad60-de50-6144-e103-000000000c00}", "ppid": 4796, "command_line": "\"C:\\Users\\buddy\\AppData\\Local\\Temp\\ipa.exe\"", "signatures": {}, "process_pid": 4832, "process_name": "C:\\Users\\buddy\\AppData\\Local\\Temp\\ipa.exe", "children": [] } ] } ] } ] }, { "pid": 1356, "image": "C:\\Windows\\System32\\svchost.exe", "timestamp": 1631903307.569, "guid": "{4e46ad60-de4b-6144-e003-000000000c00}", "ppid": 764, "command_line": "C:\\WINDOWS\\System32\\svchost.exe -k netsvcs -p -s BITS", "signatures": {}, "process_pid": 1356, "process_name": "C:\\Windows\\System32\\svchost.exe", "children": []}], [['7e7b9840296dd1b624095faa63388eddf31cea89180fe7d6e4eb01fd52ab14b9'], ['61ed4f85c992073bf9cf86a8ccf97a3836235b3026eee472b11bdd9eb577ed2a']]),
            ([{"pid": 8036, "image": "?pf86\\microsoft office\\office14\\excel.exe", "timestamp": 1631203119.713387, "guid": "placeholder", "ppid": 6452, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", "signatures": {"injection_resumethread": 250}, "process_pid": 8036, "process_name": "?pf86\\microsoft office\\office14\\excel.exe", "children": [ {"pid": 6400, "image": "?sys32\\wbem\\wmic1.exe", "timestamp": 1631203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": {"antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100}, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ {"pid": 6400, "image": "?sys32\\wbem\\wmic11.exe", "timestamp": 1631203138.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": {"antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100}, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ {"pid": 6400, "image": "?sys32\\wbem\\wmic111.exe", "timestamp": 1631303128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": {"antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100}, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": []}]}, {"pid": 6400, "image": "?sys32\\wbem\\wmic12.exe", "timestamp": 1631203148.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": {"antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100}, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": []}]}, {"pid": 6400, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": {"antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100}, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": []}, {"pid": 6400, "image": "?sys32\\wbem\\wmic3.exe", "timestamp": 1633203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": {"antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100}, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ {"pid": 6400, "image": "?sys32\\wbem\\wmic31.exe", "timestamp": 1634203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": {"antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100}, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": []}, {"pid": 6400, "image": "?sys32\\wbem\\wmic32.exe", "timestamp": 1635203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": {"antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100}, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": []}, {"pid": 6400, "image": "?sys32\\wbem\\wmic33.exe", "timestamp": 1636203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": {"antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100}, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": []}]}]}], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']])
        ]
    )
    def test_create_leaf_hashes(process_tree, expected_leaf_hashes):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        assert SandboxOntology._create_hashes(process_tree) == expected_leaf_hashes

    @staticmethod
    @pytest.mark.parametrize(
        'node, leaf_hashes, safe_leaf_hashes, expected_node',
        [ 
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d'], { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }),
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac'], { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }),
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b'], { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }),
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40'], { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }),
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd'], { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }),
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }] } ] }),
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }] }),
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] } ] } ] }),
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] } ] }),
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d'], { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }),
            ({ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, 
            ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], 
            { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": []}),
        ]
    )
    def test_remove_safe_leaves_helper(node, leaf_hashes, safe_leaf_hashes, expected_node):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        SandboxOntology._remove_safe_leaves_helper(node, leaf_hashes, safe_leaf_hashes)
        assert node == expected_node

    @staticmethod
    @pytest.mark.parametrize(
        'process_tree, leaf_hashes, safe_leaf_hashes, expected_process_tree',
        [
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }]),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }]),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }]),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }]),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }]),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }] } ] }]),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }] }]),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] } ] } ] }]),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] } ] }]),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }]),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], []),
            ([{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }, { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "children": [ { "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] }, { "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "children": [] }, { "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "children": [] } ] } ] }], [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d', 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b', '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']], ['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac', '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd', '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5'], [{ "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] } ] } ] }, { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] } ] } ] }, { "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "children": [ { "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "children": [ { "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "children": [] } ] }, { "image": "?sys32\\wbem\\wmic2.exe", "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "children": [] }, { "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "children": [ { "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "children": [] } ] } ] }])
        ]
    )
    def test_remove_safe_leaves(process_tree, leaf_hashes, safe_leaf_hashes, expected_process_tree):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        SandboxOntology._remove_safe_leaves(process_tree, leaf_hashes, safe_leaf_hashes)

        assert process_tree == expected_process_tree

    @staticmethod
    @pytest.mark.parametrize(
        "process_tree, safe_leaf_hashes, expected_process_tree",
        [
            ([{ "pid": 8036, "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "timestamp": 1631203119.713387, "guid": "placeholder", "ppid": 6452, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", "signatures": { "injection_resumethread": 250 }, "process_pid": 8036, "process_name": "?pf86\\microsoft office\\office14\\excel.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "timestamp": 1631203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "timestamp": 1631203138.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "timestamp": 1631303128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "timestamp": 1631203148.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "timestamp": 1633203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "timestamp": 1634203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "timestamp": 1635203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "timestamp": 1636203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] } ] }], ["63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5"], []),
            ([{ "pid": 8036, "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "timestamp": 1631203119.713387, "guid": "placeholder", "ppid": 6452, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", "signatures": { "injection_resumethread": 250 }, "process_pid": 8036, "process_name": "?pf86\\microsoft office\\office14\\excel.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "timestamp": 1631203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "timestamp": 1631203138.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "timestamp": 1631303128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "timestamp": 1631203148.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "timestamp": 1633203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "timestamp": 1634203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "timestamp": 1635203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "timestamp": 1636203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] } ] }], ["6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5"], [{ "pid": 8036, "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "timestamp": 1631203119.713387, "guid": "placeholder", "ppid": 6452, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", "signatures": { "injection_resumethread": 250 }, "process_pid": 8036, "process_name": "?pf86\\microsoft office\\office14\\excel.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "timestamp": 1631203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "timestamp": 1631203138.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "timestamp": 1631303128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "timestamp": 1631203148.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }]}]),
            ([{ "pid": 8036, "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "timestamp": 1631203119.713387, "guid": "placeholder", "ppid": 6452, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", "signatures": { "injection_resumethread": 250 }, "process_pid": 8036, "process_name": "?pf86\\microsoft office\\office14\\excel.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic1.exe", "node_hash": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448", "timestamp": 1631203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic11.exe", "node_hash": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464", "timestamp": 1631203138.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic111.exe", "node_hash": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "timestamp": 1631303128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic12.exe", "node_hash": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "timestamp": 1631203148.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic2.exe", "timestamp": 1632203128.413, "node_hash": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b", "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "timestamp": 1633203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "timestamp": 1634203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "timestamp": 1635203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "timestamp": 1636203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] } ] }], ["63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac", "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d", "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b"], [{ "pid": 8036, "image": "?pf86\\microsoft office\\office14\\excel.exe", "node_hash": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62", "timestamp": 1631203119.713387, "guid": "placeholder", "ppid": 6452, "command_line": "\"?pf86\\microsoft office\\office14\\excel.exe\" C:\\Users\\buddy\\AppData\\Local\\Temp\\5d3c9aebb0cae9d71e339df6dda52da6679ea1b95090eb51c66032f93516e800.xls", "signatures": { "injection_resumethread": 250 }, "process_pid": 8036, "process_name": "?pf86\\microsoft office\\office14\\excel.exe", "children": [{ "pid": 6400, "image": "?sys32\\wbem\\wmic3.exe", "node_hash": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7", "timestamp": 1633203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [ { "pid": 6400, "image": "?sys32\\wbem\\wmic31.exe", "node_hash": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40", "timestamp": 1634203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic32.exe", "node_hash": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd", "timestamp": 1635203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] }, { "pid": 6400, "image": "?sys32\\wbem\\wmic33.exe", "node_hash": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5", "timestamp": 1636203128.413, "guid": "{4e46ad60-2f38-613a-c200-000000000c00}", "ppid": 8036, "command_line": "wmic process call create 'mshta ?c\\programdata\\svyabothbrr.sct'", "signatures": { "antivm_queries_computername": 10, "checks_debugger": 10, "antivm_disk_size": 100 }, "process_pid": 6400, "process_name": "?sys32\\wbem\\wmic.exe", "children": [] } ] } ] }]),
        ]
    )
    def test_filter_process_tree_against_safe_hashes(process_tree, safe_leaf_hashes, expected_process_tree):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        filtered_process_tree = SandboxOntology._filter_process_tree_against_safe_hashes(process_tree, safe_leaf_hashes)
        assert filtered_process_tree == expected_process_tree

    @staticmethod
    @pytest.mark.parametrize("events, expected_result",
        [
            (None, []),
            ([], []),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}], [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}]),
            ([{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}], [{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}]),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}, {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}], [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}, {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}]),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}, {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 2.0, "guid": "blah"}], [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}, {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 2.0, "guid": "blah"}]),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2.0, "guid": "blah", "pguid": "blah"}, {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}], [{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}, {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2.0, "guid": "blah", "pguid": "blah"}]),
        ]
    )
    def test_get_events(events, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so = SandboxOntology(events=events)
        actual_result = so.get_events()
        assert actual_result == expected_result

    # TODO: implement this
    # @staticmethod
    # def test_run_signatures():
    #     from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
    #     o = SandboxOntology()
    #     actual_result = o.run_signatures()
    #     assert actual_result is True

    @staticmethod
    @pytest.mark.parametrize("artifact_list, expected_result",
        [
            (None, None),
            ([], None),
            ([{"name": "blah", "path": "blah", "description": "blah", "to_be_extracted": True}], None),
            ([{"name": "blah", "path": "blah", "description": "blah", "to_be_extracted": False}], None),
        ]
    )
    def test_handle_artifacts(artifact_list, expected_result, dummy_request_class):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        r = dummy_request_class()
        o = SandboxOntology()
        actual_result = o.handle_artifacts(artifact_list, r)
        assert actual_result == expected_result

