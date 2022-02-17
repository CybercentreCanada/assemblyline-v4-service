from cmath import exp
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
        result_heuristic_equality = this.heuristic.attack_ids == that.heuristic.attack_ids and \
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
        open_manifest.write(
            "name: Sample\nversion: sample\ndocker_config: \n  image: sample\nheuristics:\n  - heur_id: 17\n"
            "    name: blah\n    description: blah\n    filetype: '*'\n    score: 250")


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
                             [(None, None, None, None,
                               {"image": None, "pid": None, "timestamp": None, "guid": None, "pguid": None,
                                "signatures": {}}),
                              (1, "blah", 1.0, "blah",
                               {"image": "blah", "pid": 1, "timestamp": 1.0, "guid": "blah", "pguid": None,
                                "signatures": {}}), ])
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
    @pytest.mark.parametrize("pid, ppid, image, command_line, timestamp, guid, pguid",
                             [
                                 (None, None, None, None, None, None, None),
                                 (1, 1, "blah", "blah", 1.0, "blah", "blah"),
                             ]
                             )
    def test_init(pid, ppid, image, command_line, timestamp, guid, pguid):
        from assemblyline_v4_service.common.dynamic_service_helper import ProcessEvent
        p = ProcessEvent(pid=pid, ppid=ppid, image=image, command_line=command_line,
                         timestamp=timestamp, guid=guid, pguid=pguid)
        assert p.pid == pid
        assert p.ppid == ppid
        assert p.image == image
        assert p.command_line == command_line
        assert p.timestamp == timestamp
        assert p.guid == guid
        assert p.pguid == pguid


class TestNetworkEvent:
    @staticmethod
    @pytest.mark.parametrize("protocol, src_ip, src_port, domain, dest_ip, dest_port, pid, timestamp, guid",
                             [
                                 (None, None, None, None, None, None, None, None, None),
                                 ("blah", "blah", 1, "blah", "blah", 1, 1, 1.0, "blah"),
                             ]
                             )
    def test_init(protocol, src_ip, src_port, domain, dest_ip, dest_port, pid, timestamp, guid):
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkEvent
        n = NetworkEvent(protocol=protocol, src_ip=src_ip, src_port=src_port, domain=domain,
                         dest_ip=dest_ip, dest_port=dest_port, pid=pid, timestamp=timestamp, guid=guid)
        assert n.protocol == protocol
        assert n.src_port == src_port
        assert n.domain == domain
        assert n.dest_ip == dest_ip
        assert n.dest_port == dest_port
        assert n.pid == pid
        assert n.timestamp == timestamp
        assert n.guid == guid


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
    @pytest.mark.parametrize(
        "events, expected_events, expected_sorted_events, expected_process_events, expected_network_events, expected_process_event_dicts, expected_network_event_dicts, expected_event_dicts",
        [([],
          [],
          [],
          [],
          [],
          {},
          {},
          {})])
    def test_init(events, expected_events, expected_sorted_events, expected_process_events, expected_network_events,
                  expected_process_event_dicts, expected_network_event_dicts, expected_event_dicts):
        from assemblyline_v4_service.common.dynamic_service_helper import Events
        e = Events(events=events)
        assert e.events == expected_events
        assert e.sorted_events == expected_sorted_events
        assert e.process_events == expected_process_events
        assert e.network_events == expected_network_events
        assert e.process_event_dicts == expected_process_event_dicts
        assert e.network_event_dicts == expected_network_event_dicts
        assert e.event_dicts == expected_event_dicts

    @staticmethod
    @pytest.mark.parametrize(
        "events, validated_events_num",
        [([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah",
            "pguid": "blah"}],
          1),
         ([{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1,
            "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah", "pguid": None}],
          1),
         ([{}],
          0), ])
    def test_validate_events(events, validated_events_num):
        from assemblyline_v4_service.common.dynamic_service_helper import Events
        if validated_events_num:
            assert len(Events._validate_events(events)) == validated_events_num
        else:
            with pytest.raises(ValueError):
                Events._validate_events(events)

    @staticmethod
    @pytest.mark.parametrize(
        "events, validated_events_num",
        [([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah",
            "pguid": "blah"}],
          1),
         ([{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1,
            "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah", "pguid": None}],
          0), ])
    def test_get_process_events(events, validated_events_num):
        from assemblyline_v4_service.common.dynamic_service_helper import Events
        validated_events = Events._validate_events(events)
        assert len(Events._get_process_events(validated_events)) == validated_events_num

    @staticmethod
    @pytest.mark.parametrize(
        "events, validated_events_num",
        [([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah",
            "pguid": "blah"}],
          0),
         ([{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1,
            "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah", "pguid": None}],
          1), ])
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
                             [([{"pid": 1, "image": "blah", "timestamp": 1, "guid": None, "pguid": None}],
                               {1: {'guid': None, 'image': 'blah', 'pid': 1, 'timestamp': 1, "pguid": None, "signatures": {}}}),
                              ([{"pid": 1, "image": "blah", "timestamp": 1, "guid": None, "pguid": None},
                                {"pid": 2, "image": "blah", "timestamp": 1, "guid": None, "pguid": None}],
                               {1: {'guid': None, 'image': 'blah', 'pid': 1, 'timestamp': 1, "pguid": None, "signatures": {}},
                                2: {'guid': None, 'image': 'blah', 'pid': 2, 'timestamp': 1, "pguid": None, "signatures": {}}}),
                              ([{"pid": 1, "image": "blah", "timestamp": 1, "guid": "a", "pguid": None},
                                {"pid": 2, "image": "blah", "timestamp": 1, "guid": "b", "pguid": None}],
                               {"a": {'guid': "a", 'image': 'blah', 'pid': 1, 'timestamp': 1, "pguid": None, "signatures": {}},
                                "b": {'guid': "b", 'image': 'blah', 'pid': 2, 'timestamp': 1, "pguid": None, "signatures": {}}}), ])
    def test_convert_events_to_dict(events, expected_events_dict):
        from assemblyline_v4_service.common.dynamic_service_helper import Event, Events
        event_objects = [
            Event(
                pid=event["pid"],
                image=event["image"],
                timestamp=event["timestamp"],
                guid=event["guid"]) for event in events]
        assert Events._convert_events_to_dict(event_objects) == expected_events_dict


class TestSandboxOntology:
    @staticmethod
    @pytest.mark.parametrize("events, expected_events", [([], [])])
    def test_init(events, expected_events):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so = SandboxOntology(events=events)
        assert so.events == expected_events

    @staticmethod
    @pytest.mark.parametrize(
        "events_dict, expected_result",
        [
            # No processes
            ({}, []),
            # One process
            (
                {1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None}},
                [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                  "timestamp": 1, "process_pid": 1, "process_name": "blah", "guid": None, "pguid": None, "children": [], "signatures": {}}]
            ),
            # One parent process and one child process
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah",
                     "command_line": "blah", "timestamp": 1, "process_pid": 1, "process_name": "blah", "guid": None, "pguid": None,
                     "children": [{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "timestamp": 1, "process_pid": 2, "process_name": "blah", "guid": None, "pguid": None, "children": [], "signatures": {}}, ], "signatures": {}
                     },
                ],
            ),
            # Two unrelated processes
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                     "timestamp": 1, "process_pid": 1, "process_name": "blah", "guid": None, "pguid": None, "children": [], "signatures": {}},
                    {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah",
                     "timestamp": 1, "process_pid": 2, "process_name": "blah", "guid": None, "pguid": None, "children": [], "signatures": {}},
                ],
            ),
            # Three processes consisting of a parent-child relationship and a rando process
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None},
                    3: {"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                     "timestamp": 1, "process_pid": 1, "process_name": "blah", "guid": None, "pguid": None, "children": [], "signatures": {}},
                    {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah",
                     "timestamp": 1, "process_pid": 2, "process_name": "blah", "guid": None, "pguid": None,
                     "children": [{"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah",
                                   "timestamp": 1, "process_pid": 3, "process_name": "blah", "guid": None, "pguid": None, "children": [], "signatures": {}}], "signatures": {}
                     },
                ],
            ),
            # Three processes consisting of a grandparent-parent-child relationship and one rando process
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2, "guid": None, "pguid": None},
                    3: {"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 3, "guid": None, "pguid": None},
                    4: {"pid": 4, "ppid": 4, "image": "blah", "command_line": "blah", "timestamp": 2, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                     "timestamp": 1, "process_pid": 1, "process_name": "blah", "guid": None, "pguid": None,
                     "children": [{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "timestamp": 2, "process_pid": 2, "process_name": "blah", "guid": None, "pguid": None,
                                   "children": [{"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah",
                                                 "timestamp": 3, "process_pid": 3, "process_name": "blah", "guid": None, "pguid": None,
                                                 "children": [], "signatures": {}}, ], "signatures": {}}], "signatures": {}
                     },
                    {"pid": 4, "ppid": 4, "image": "blah", "command_line": "blah",
                     "timestamp": 2, "process_pid": 4, "process_name": "blah", "guid": None, "pguid": None, "children": [], "signatures": {}}
                ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2, "guid": None, "pguid": None},
                    3: {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3, "guid": None, "pguid": None},
                    4: {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                     "timestamp": 1, "process_pid": 1, "process_name": "blah", "guid": None, "pguid": None,
                     "children": [{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "timestamp": 2, "process_pid": 2, "process_name": "blah", "guid": None, "pguid": None,
                                   "children": [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah",
                                                 "timestamp": 4,  "process_pid": 4, "process_name": "blah", "guid": None, "pguid": None,
                                                 "children": [], "signatures": {}}], "signatures": {}},
                                  {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "timestamp": 3,  "process_pid": 3, "process_name": "blah", "guid": None, "pguid": None,
                                   "children": [], "signatures": {}}
                                  ], "signatures": {}
                     },
                ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship with non-ordered times
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3, "guid": None, "pguid": None},
                    3: {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2, "guid": None, "pguid": None},
                    4: {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                     "timestamp": 1, "process_pid": 1, "process_name": "blah", "guid": None, "pguid": None,
                     "children": [{"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "timestamp": 2, "process_pid": 3, "process_name": "blah", "guid": None, "pguid": None,
                                   "children": [], "signatures": {}},
                                  {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "timestamp": 3, "process_pid": 2, "process_name": "blah", "guid": None, "pguid": None,
                                   "children": [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah",
                                                 "timestamp": 4, "process_pid": 4, "process_name": "blah", "guid": None, "pguid": None,
                                                 "children": [], "signatures": {}}], "signatures": {}},
                                  ], "signatures": {}
                     },
                ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship
            # with non-ordered times using guids
            (
                {
                    "a": {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                          "timestamp": 1, "guid": "a", "pguid": None},
                    "b": {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                          "timestamp": 3, "guid": "b", "pguid": "a"},
                    "c": {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah",
                          "timestamp": 2, "guid": "c", "pguid": "a"},
                    "d": {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah",
                          "timestamp": 4, "guid": "d", "pguid": "b"},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a",
                     "pguid": None, "process_pid": 1, "process_name": "blah",
                     "children": [{"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "timestamp": 2, "guid": "c", "pguid": "a", "process_pid": 3, "process_name": "blah",
                                   "children": [], "signatures": {}},
                                  {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "timestamp": 3, "guid": "b", "pguid": "a", "process_pid": 2, "process_name": "blah",
                                   "children": [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah",
                                                 "timestamp": 4, "guid": "d", "pguid": "b", "process_pid": 4,
                                                 "process_name": "blah",
                                                 "children": [], "signatures": {}}], "signatures": {}},
                                  ], "signatures": {}
                     },
                ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship
            # with non-ordered times using guids
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
                     "children": [{"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2,
                                  "guid": None, "pguid": None, "process_pid": 3, "process_name": "blah",
                                   "children": [], "signatures": {}},
                                  {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3,
                                  "guid": None, "pguid": None, "process_pid": 2, "process_name": "blah",
                                   "children": [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah",
                                                "timestamp": 4, "guid": None, "pguid": None, "process_pid": 4,
                                                 "process_name": "blah", "children": [], "signatures": {}}], "signatures": {}}, ], "signatures": {}
                     },
                ],
            ),
        ]
    )
    def test_convert_events_dict_to_tree(events_dict, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        actual_result = SandboxOntology._convert_events_dict_to_tree(events_dict)
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
                             [(None, None),
                              ({"path": "blah", "name": "blah", "description": "blah", "to_be_extracted": True},
                               None),
                              ({"path": "blah", "name": "123_hollowshunter/hh_process_123_blah.exe",
                                "description": "blah", "to_be_extracted": True},
                               "HollowsHunter Injected Portable Executable"),
                              ({"path": "blah", "name": "123_hollowshunter/hh_process_123_blah.shc",
                                "description": "blah", "to_be_extracted": True},
                               None),
                              ({"path": "blah", "name": "123_hollowshunter/hh_process_123_blah.dll",
                                "description": "blah", "to_be_extracted": True},
                               "HollowsHunter Injected Portable Executable"), ])
    def test_handle_artifact(artifact, expected_result_section_title):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Artifact, HOLLOWSHUNTER_TITLE
        from assemblyline_v4_service.common.result import ResultSection, Heuristic

        if artifact is None:
            with pytest.raises(Exception):
                SandboxOntology._handle_artifact(artifact, None)
            return

        expected_result_section = None
        if expected_result_section_title is not None:
            expected_result_section = ResultSection(expected_result_section_title)
            expected_result_section.add_line("HollowsHunter dumped the following:")
            expected_result_section.add_line(f"\t- {artifact['name']}")
            expected_result_section.add_tag("dynamic.process.file_name", artifact["name"])
            if expected_result_section_title == HOLLOWSHUNTER_TITLE:
                heur = Heuristic(17)
                if ".exe" in artifact["name"]:
                    heur.add_signature_id("hollowshunter_exe")
                elif ".dll" in artifact["name"]:
                    heur.add_signature_id("hollowshunter_dll")

                expected_result_section.set_heuristic(heur)
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

            additional_artifact = Artifact(name="321_hollowshunter/hh_process_321_blah.dll",
                                           path="blah", description="blah", to_be_extracted=False)
            SandboxOntology._handle_artifact(additional_artifact, parent_result_section)
            expected_result_section.add_line(f"\t- {additional_artifact.name}")
            expected_result_section.add_tag("dynamic.process.file_name", additional_artifact.name)
            expected_result_section.heuristic.add_signature_id("hollowshunter_dll")

            assert check_section_equality(actual_result_section, expected_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "process_list, signatures, expected_result",
        [(None, [],
          {}),
         ([],
          [],
          {}),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None}],
          [{"pid": 1, "name": "blah", "score": 1}],
          {1:
           {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None,
            "signatures": {"blah": 1}}}),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None}],
          [{"pid": 1, "name": "blah", "score": 1}],
          {2:
           {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": None, "pguid": None,
            "signatures": {}}}),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a", "pguid": None}],
          [{"pid": 1, "name": "blah", "score": 1}],
          {
             "a":
             {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a", "pguid": None,
              "signatures": {}}}),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a", "pguid": None}],
          [{"pid": 1, "name": "blah", "score": 1}],
          {
             "a":
             {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "a", "pguid": None,
              "signatures": {"blah": 1}}}), ])
    def test_match_signatures_to_events(process_list, signatures, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        o = SandboxOntology(process_list)
        actual_result = o._match_signatures_to_events(o.event_dicts, signature_dicts=signatures)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "event_list, signatures, safelist, expected_result, tree_type",
        [(None, None, [],
          [],
          "PROCESS"),
         ([],
          None, [],
          [],
          "PROCESS"),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah",
            "pguid": "blahblah"}],
          None, [],
          [{'pid': 1, 'image': 'blah', 'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52',
            'timestamp': 1, 'guid': 'blah', 'ppid': 1, 'pguid': 'blahblah', 'command_line': 'blah', 'process_pid': 1,
            'process_name': 'blah', 'children': [], "signatures": {}}],
          "PROCESS"),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah",
            "pguid": "blahblah"},
           {"pid": 2, "ppid": 1, "image": "blah2", "command_line": "blah2", "timestamp": 2, "guid": "blah2",
            "pguid": "blah"}],
          None, [],
          [{'pid': 1, 'image': 'blah', 'timestamp': 1, 'guid': 'blah', 'ppid': 1, 'pguid': 'blahblah',
            'command_line': 'blah', 'process_pid': 1, 'process_name': 'blah',
            'children':
            [{'pid': 2, 'image': 'blah2', 'timestamp': 2, 'guid': 'blah2', 'ppid': 1, 'pguid': 'blah',
              'command_line': 'blah2', 'process_pid': 2, 'process_name': 'blah2', 'children': [],
              'tree_id': '28fb5ed121e549f67b678d225bb2fc9971ed02c18a087f8fa9b05bf18a23d9e1', "signatures": {}}],
            'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52', "signatures": {}}],
          "PROCESS"),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah",
            "pguid": "blahblah"},
           {"pid": 2, "ppid": 1, "image": "blah2", "command_line": "blah2", "timestamp": 2, "guid": "blah2",
            "pguid": "blah"},
           {"pid": 3, "ppid": 3, "image": "blah3", "command_line": "blah3", "timestamp": 1, "guid": "blah3",
            "pguid": "blah3"},
           {"pid": 4, "ppid": 3, "image": "blah4", "command_line": "blah4", "timestamp": 2, "guid": "blah4",
            "pguid": "blah3"}],
          None, ["55459caaa8ca94a90de5643a6a930e1b19bab480982607327081f46eb86f816c"],
          [{'pid': 1, 'image': 'blah', 'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52',
            'timestamp': 1, 'guid': 'blah', 'ppid': 1, 'pguid': 'blahblah', 'command_line': 'blah', 'process_pid': 1,
            'process_name': 'blah',
            'children':
            [{'pid': 2, 'image': 'blah2', 'tree_id': '28fb5ed121e549f67b678d225bb2fc9971ed02c18a087f8fa9b05bf18a23d9e1',
              'timestamp': 2, 'guid': 'blah2', 'ppid': 1, 'pguid': 'blah', 'command_line': 'blah2', 'process_pid': 2,
              'process_name': 'blah2', 'children': [], "signatures": {}}], "signatures": {}}],
          "PROCESS"),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah",
            "pguid": "blahblah"},
           {"pid": 2, "ppid": 1, "image": "blah2", "command_line": "blah2", "timestamp": 2, "guid": "blah2",
            "pguid": "blah"},
           {"pid": 3, "ppid": 3, "image": "blah3", "command_line": "blah3", "timestamp": 1, "guid": "blah3",
            "pguid": "blah3"},
           {"pid": 4, "ppid": 3, "image": "blah4", "command_line": "blah4", "timestamp": 2, "guid": "blah4",
            "pguid": "blah3"},
           {"pid": 4, "image": "blah4", "timestamp": 3, "guid": "blah5", "pguid": "blah4", "dest_ip": "1.1.1.1",
            "dest_port": 443, "domain": "blah.com", "protocol": "tcp", "src_ip": "2.2.2.2", "src_port": 9999}],
          None, ["55459caaa8ca94a90de5643a6a930e1b19bab480982607327081f46eb86f816c"],
          [{'pid': 1, 'image': 'blah', 'timestamp': 1, 'guid': 'blah', 'pguid': 'blahblah', 'ppid': 1,
            'command_line': 'blah', 'process_pid': 1, 'process_name': 'blah',
            'children':
            [{'pid': 2, 'image': 'blah2', 'timestamp': 2, 'guid': 'blah2', 'pguid': 'blah', 'ppid': 1,
              'command_line': 'blah2', 'process_pid': 2, 'process_name': 'blah2', 'children': [], "signatures": {},
              'tree_id': '28fb5ed121e549f67b678d225bb2fc9971ed02c18a087f8fa9b05bf18a23d9e1'}],
            'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52', "signatures": {}},
           {'pid': 3, 'image': 'blah3', 'timestamp': 1, 'guid': 'blah3', 'pguid': 'blah3', 'ppid': 3,
            'command_line': 'blah3', 'process_pid': 3, 'process_name': 'blah3',
            'children':
            [{'pid': 4, 'image': 'blah4', 'timestamp': 2, 'guid': 'blah4', 'pguid': 'blah3', 'ppid': 3,
              'command_line': 'blah4', 'process_pid': 4, 'process_name': 'blah4',
              'children':
              [{'pid': 4, 'image': 'blah4', 'timestamp': 3, 'guid': 'blah5', 'pguid': 'blah4', 'protocol': 'tcp',
                'src_ip': '2.2.2.2', 'src_port': 9999, 'domain': 'blah.com', 'dest_ip': '1.1.1.1', 'dest_port': 443,
                'children': [], "signatures": {}, "process_pid": 4, "process_name": "blah4",
                'tree_id': 'b917df6cdf06e8aced76547e77c77d9fe1fdd5fa6d84604690b26ac17ab6de35'}], "signatures": {},
              'tree_id': '55459caaa8ca94a90de5643a6a930e1b19bab480982607327081f46eb86f816c'}], "signatures": {},
            'tree_id': '15405363bfd90e1733ceb9803c8998c5223966ce0273608f8c6c4d82906267b7', "signatures": {}}],
          "EVENT"),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1,
             "guid": "blah", "pguid": "blahblah"}],
          [{"pid": 1, "name": "blah", "score": 1}],
          [],
          [{"children": [],
            "pid": 1, "ppid": 1, "process_name": "blah", "process_pid": 1, "image": "blah",
            'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52',
                                 "command_line": "blah", "timestamp": 1, "guid": "blah", "pguid": "blahblah",
                                 "signatures": {"blah": 1}}], "EVENT"),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1,
                                 "guid": "blah", "pguid": "blahblah"}],
          [{"pid": 1, "name": "blah", "score": 1}],
          [],
          [{"children": [],
            "pid": 2, "ppid": 1, "process_name": "blah", "process_pid": 2, "image": "blah",
                                 'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52',
                                 "command_line": "blah", "timestamp": 1, "guid": "blah", "pguid": "blahblah",
                                 "signatures": {}}], "EVENT"),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1,
                                 "guid": "blah", "pguid": "blahblah"}],
          [{"pid": 1, "name": "blah", "score": 1}],
          ["blah"],
          [{"children": [],
            "pid": 2, "ppid": 1, "process_name": "blah", "process_pid": 2, "image": "blah",
                                 'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52',
                                 "command_line": "blah", "timestamp": 1, "guid": "blah", "pguid": "blahblah",
                                 "signatures": {}}], "EVENT"),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1,
                                 "guid": "blah", "pguid": "blahblah"}],
          [{"pid": 1, "name": "blah", "score": 1}],
          ["8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52"],
          [], "EVENT")
         ])
    def test_get_event_tree(event_list, signatures, safelist, expected_result, tree_type):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        o = SandboxOntology(event_list)
        actual_result = o.get_event_tree(signatures=signatures, tree_type=tree_type, safelist=safelist)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "parent, node, expected_node, expected_tree_ids",
        [
            ("", {"image": "got the image",
                  "children": [{"image": "image number 2", "children": []},
                               {"image": "image number 3", "children": []}]},
                {"image": "got the image",
                 "tree_id": "b71bf6eacf36ecdf07b3f1efa5d6f50725271ca85369b966e19da5b76c175b5b",
                 "children": [{"image": "image number 2",
                               "tree_id": "294156e02fb77c860933c93da8629dbceab367629a1ff9af68ff4b03c8596b17",
                               "children": []},
                              {"image": "image number 3",
                               "tree_id": "0483e740e929697527964c71227dd76403cdc91ca16e7a4a9a430f734481f129",
                               "children": []}]},
             ['294156e02fb77c860933c93da8629dbceab367629a1ff9af68ff4b03c8596b17',
              '0483e740e929697527964c71227dd76403cdc91ca16e7a4a9a430f734481f129']),
            ("blahblah", {"image": "got the image", "children": [{"image": "image number 2", "children": []},
                                                                 {"image": "image number 3", "children": []}]},
             {"image": "got the image", "tree_id": "66ca3e01980a462ae88cf5e329ca479519f75d87192e93a8573e661bedb0cb9c",
              "children": [{"image": "image number 2",
                            "tree_id": "9dc17d47ccef093c965c150401b717ba27728dd2c6360322526bd4c19493b154",
                            "children": []},
                           {"image": "image number 3",
                            "tree_id": "020951694e1d88b34a8a3409d1f6f027173302728800e000af9d874ff9a3004d",
                            "children": []}]},
             ['9dc17d47ccef093c965c150401b717ba27728dd2c6360322526bd4c19493b154',
              '020951694e1d88b34a8a3409d1f6f027173302728800e000af9d874ff9a3004d'])
        ]
    )
    def test_create_hashed_node(parent, node, expected_node, expected_tree_ids):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        tree_ids = []
        SandboxOntology._create_hashed_node(parent, node, tree_ids)
        assert tree_ids == expected_tree_ids
        assert node == expected_node

    @staticmethod
    @pytest.mark.parametrize("process_tree, expected_process_tree, expected_process_tree_ids",
                             [([{"image": "?pf86\\microsoft office\\office14\\excel.exe",
                                 "children":
                                 [{"image": "?sys32\\wbem\\wmic1.exe",
                                   "children":
                                   [{"image": "?sys32\\wbem\\wmic11.exe",
                                     "children": [{"image": "?sys32\\wbem\\wmic111.exe", "children": []}]},
                                    {"image": "?sys32\\wbem\\wmic12.exe", "children": []}]},
                                  {"image": "?sys32\\wbem\\wmic2.exe", "children": []},
                                  {"image": "?sys32\\wbem\\wmic3.exe",
                                   "children":
                                   [{"image": "?sys32\\wbem\\wmic31.exe", "children": []},
                                    {"image": "?sys32\\wbem\\wmic32.exe", "children": []},
                                    {"image": "?sys32\\wbem\\wmic33.exe", "children": []}]}]}],
                               [{"image": "?pf86\\microsoft office\\office14\\excel.exe",
                                 "tree_id": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62",
                                 "children":
                                 [{"image": "?sys32\\wbem\\wmic1.exe",
                                   "tree_id": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448",
                                   "children":
                                   [{"image": "?sys32\\wbem\\wmic11.exe",
                                     "tree_id": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464",
                                     "children":
                                     [{"image": "?sys32\\wbem\\wmic111.exe",
                                       "tree_id": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac",
                                       "children": []}]},
                                    {"image": "?sys32\\wbem\\wmic12.exe",
                                     "tree_id": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d",
                                     "children": []}]},
                                  {"image": "?sys32\\wbem\\wmic2.exe",
                                   "tree_id": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b",
                                   "children": []},
                                  {"image": "?sys32\\wbem\\wmic3.exe",
                                   "tree_id": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7",
                                   "children":
                                   [{"image": "?sys32\\wbem\\wmic31.exe",
                                     "tree_id": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40",
                                     "children": []},
                                    {"image": "?sys32\\wbem\\wmic32.exe",
                                     "tree_id": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd",
                                     "children": []},
                                    {"image": "?sys32\\wbem\\wmic33.exe",
                                     "tree_id": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5",
                                     "children": []}]}]}],
                               [['63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac',
                                 '6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d',
                                 'a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b',
                                 '6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40',
                                 '099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd',
                                 '4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5']]), ])
    def test_create_tree_ids(process_tree, expected_process_tree, expected_process_tree_ids):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        tree_ids = SandboxOntology._create_tree_ids(process_tree)
        assert tree_ids == expected_process_tree_ids
        assert process_tree == expected_process_tree

    @staticmethod
    @pytest.mark.parametrize(
        'node, safe_tree_ids, expected_node',
        [
            ({"image": "a", "tree_id": "a", "children": []}, [], {"image": "a", "tree_id": "a", "children": []}),
            ({"image": "a", "tree_id": "a", "children": []}, ["a"], {"image": "a", "tree_id": "a", "children": []}),
            ({"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b", "children": []}]}, [],
             {"image": "a", "tree_id": "a", "children": [
                 {"image": "b", "tree_id": "b", "children": []}]}),
            ({"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b", "children": []}]}, ["b"],
             {'children': [], 'image': 'a', 'tree_id': 'b'}),
            ({"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b", "children": []}]}, ["a"],
             {'children': [{'children': [], 'image': 'b', 'tree_id': 'b'}],
              'image': 'a', 'tree_id': 'a'}),
            ({"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b", "children": []},
                           {"image": "c", "tree_id": "c", "children": []}]}, [],
             {'children': [{'children': [], 'image': 'b', 'tree_id': 'b'},
                           {'children': [], 'image': 'c', 'tree_id': 'c'}], 'image': 'a', 'tree_id': 'a'}),
            ({"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b", "children": []},
                           {"image": "c", "tree_id": "c", "children": []}]}, ["b"],
             {'children': [{'children': [], 'image': 'c', 'tree_id': 'c'}],
              'image': 'a', 'tree_id': 'a'}),
            ({"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b", "children": []},
                           {"image": "c", "tree_id": "c", "children": []}]}, ["c"],
             {'children': [{'children': [], 'image': 'b', 'tree_id': 'b'}],
              'image': 'a', 'tree_id': 'a'}),
            ({"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b",
                            "children": [{"image": "d", "tree_id": "d", "children": []}]},
                           {"image": "c", "tree_id": "c", "children": []}]}, ["c"],
             {'children': [{'children': [{"image": "d", "tree_id": "d", "children": []}],
                            'image': 'b', 'tree_id': 'b'}], 'image': 'a', 'tree_id': 'a'}),
            ({"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b",
                            "children": [{"image": "d", "tree_id": "d", "children": []}]},
                           {"image": "c", "tree_id": "c", "children": []}]}, ["d"],
             {'children': [{'children': [], 'image': 'c', 'tree_id': 'c'}],
              'image': 'a', 'tree_id': 'a'}),
            ({"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b", "children": []},
                           {"image": "c", "tree_id": "c",
                            "children": [{"image": "d", "tree_id": "d", "children": []}]}]}, ["d"],
             {"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b", "children": []}]}),
            ({"image": "a", "tree_id": "a",
              "children": [{"image": "b", "tree_id": "b", "children": []},
                           {"image": "c", "tree_id": "c",
                            "children": [{"image": "d", "tree_id": "d", "children": []}]}]}, ["b"],
             {"image": "a", "tree_id": "a",
              "children": [{"image": "c", "tree_id": "c",
                            "children": [{"image": "d", "tree_id": "d",
                                          "children": []}]}]}),
        ]
    )
    def test_remove_safe_leaves_helper(node, safe_tree_ids, expected_node):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        _ = SandboxOntology._remove_safe_leaves_helper(node, safe_tree_ids)
        assert node == expected_node

    @staticmethod
    @pytest.mark.parametrize('process_tree, safe_tree_ids, expected_process_tree',
                             [([{"image": "a", "children": [],
                                 "tree_id": "blah"}],
                               [],
                               [{"image": "a", "children": [],
                                 "tree_id": "blah"}]),
                              ([{"image": "a", "children": [],
                                 "tree_id": "blah"}],
                               ["blah"],
                               []),
                              ([{"image": "a", "children": [],
                                 "tree_id": "blah"},
                                {"image": "b", "children": [],
                                 "tree_id": "blahblah"}],
                               ["blah"],
                               [{"image": "b", "children": [],
                                 "tree_id": "blahblah"}]),
                              ([{"image": "a", "children": [],
                                 "tree_id": "blah"},
                                {"image": "b", "children": [],
                                 "tree_id": "blahblah"}],
                               ["blahblah"],
                               [{"image": "a", "children": [],
                                 "tree_id": "blah"}]),
                              ([{"image": "a", "children": [{"image": "b", "children": [],
                                                             "tree_id": "b"}],
                                 "tree_id": "a"},
                                {"image": "c", "children": [{"image": "d", "children": [],
                                                             "tree_id": "d"}],
                                 "tree_id": "c"}],
                               [],
                               [{"image": "a", "children": [{"image": "b", "children": [],
                                                             "tree_id": "b"}],
                                 "tree_id": "a"},
                                {"image": "c", "children": [{"image": "d", "children": [],
                                                             "tree_id": "d"}],
                                 "tree_id": "c"}]),
                              ([{"image": "a", "children": [{"image": "b", "children": [],
                                                             "tree_id": "b"}],
                                 "tree_id": "a"},
                                {"image": "c", "children": [{"image": "d", "children": [],
                                                             "tree_id": "d"}],
                                 "tree_id": "c"}],
                               ["a"],
                               [{"image": "a", "children": [{"image": "b", "children": [],
                                                             "tree_id": "b"}],
                                 "tree_id": "a"},
                                {"image": "c", "children": [{"image": "d", "children": [],
                                                             "tree_id": "d"}],
                                 "tree_id": "c"}]),
                              ([{"image": "a", "children": [{"image": "b", "children": [],
                                                             "tree_id": "b"}],
                                 "tree_id": "a"},
                                {"image": "c", "children": [{"image": "d", "children": [],
                                                             "tree_id": "d"}],
                                 "tree_id": "c"}],
                               ["b"],
                               [{"image": "c", "children": [{"image": "d", "children": [],
                                                             "tree_id": "d"}],
                                 "tree_id": "c"}]), ])
    def test_remove_safe_leaves(process_tree, safe_tree_ids, expected_process_tree):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        SandboxOntology._remove_safe_leaves(process_tree, safe_tree_ids)
        assert process_tree == expected_process_tree

    @staticmethod
    @pytest.mark.parametrize("event_tree, safe_tree_ids, expected_event_tree",
                             [([],
                               [],
                               []),
                              ([{"image": "a", "children": [],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}],
                               [],
                               [{"image": "a", "children": [],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}]),
                              ([{"image": "a", "children": [],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}],
                               ["ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"],
                               []),
                              ([{"image": "a",
                                 "children":
                                 [{"image": "b", "children": [],
                                   "tree_id": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"}],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}],
                               [],
                               [{"image": "a",
                                 "children":
                                 [{"image": "b", "children": [],
                                   "tree_id": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"}],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}]),
                              ([{"image": "a",
                                 "children":
                                 [{"image": "b", "children": [],
                                   "tree_id": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"}],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}],
                               ["d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"],
                               []),
                              ([{"image": "a",
                                 "children":
                                 [{"image": "b", "children": [],
                                   "tree_id": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"}],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}],
                               ["ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"],
                               [{"image": "a",
                                 "children":
                                 [{"image": "b", "children": [],
                                   "tree_id": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"}],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}]),
                              ([{"image": "a",
                                 "children":
                                 [{"image": "b", "children": [],
                                   "tree_id": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"}],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
                                {"image": "c",
                                 "children":
                                 [{"image": "d", "children": [],
                                   'tree_id': 'c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04'}],
                                 "tree_id": '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6'}],
                               ["d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"],
                               [{
                                   'children':
                                   [{'children': [],
                                     'image': 'd',
                                     'tree_id': 'c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04'}],
                                   'image': 'c',
                                   'tree_id': '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6'}]),
                              ([{"image": "a",
                                 "children":
                                 [{"image": "b", "children": [],
                                   "tree_id": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"}],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
                                {"image": "c",
                                 "children":
                                 [{"image": "d", "children": [],
                                   'tree_id': 'c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04'}],
                                 "tree_id": '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6'}],
                               ["2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"],
                               [{"image": "a",
                                 "children":
                                 [{"image": "b", "children": [],
                                   "tree_id": 'd107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef'}],
                                 "tree_id": 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'},
                                {"image": "c",
                                 "children":
                                 [{"image": "d", "children": [],
                                   "tree_id": 'c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04'}],
                                 "tree_id": '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6'}]),
                              ([{"image": "a",
                                 "children":
                                 [{"image": "b", "children": [],
                                   "tree_id": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"}],
                                 "tree_id": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
                                {"image": "c",
                                 "children":
                                 [{"image": "d", "children": [],
                                   'tree_id': 'c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04'}],
                                 "tree_id": '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6'}],
                               ["c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04"],
                               [{"image": "a",
                                 "children":
                                 [{"image": "b", "children": [],
                                   "tree_id": 'd107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef'}],
                                 "tree_id": 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'}]), ])
    def test_filter_event_tree_against_safe_tree_ids(event_tree, safe_tree_ids, expected_event_tree):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        filtered_event_tree = SandboxOntology._filter_event_tree_against_safe_tree_ids(event_tree, safe_tree_ids)
        assert filtered_event_tree == expected_event_tree

    @staticmethod
    @pytest.mark.parametrize(
        "events, expected_result",
        [(None, []),
         ([],
          []),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah",
            "pguid": "blah"}],
          [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah",
            "pguid": "blah", "signatures": {}}]),
         ([{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1,
            "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}],
          [{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1,
            "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah", "signatures": {}}]),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah",
            "pguid": "blah"},
           {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1,
            "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}],
          [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah",
            "pguid": "blah", "signatures": {}},
           {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1,
            "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah", "signatures": {}}]),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2.0, "guid": "blah",
            "pguid": "blah"},
           {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1,
            "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah"}],
          [{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1,
            "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah", "pguid": "blah", "signatures": {}},
           {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2.0, "guid": "blah",
            "pguid": "blah", "signatures": {}}]), ])
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
                             [(None, None),
                              ([],
                               None),
                              ([{"name": "blah", "path": "blah", "description": "blah", "to_be_extracted": True}],
                               None),
                              ([{"name": "blah", "path": "blah", "description": "blah", "to_be_extracted": False}],
                               None), ])
    def test_handle_artifacts(artifact_list, expected_result, dummy_request_class):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        r = dummy_request_class()
        o = SandboxOntology()
        actual_result = o.handle_artifacts(artifact_list, r)
        assert actual_result == expected_result
