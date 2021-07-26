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
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah"}], 1),
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
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah"}], 1),
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
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah"}], 0),
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
                    [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "children": []}]
            ),
            # One parent process and one child process
            (
                    {
                        1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1},
                        2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1},
                    },
                    [
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1,
                         "children":
                             [{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "children": []},]
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
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "children": []},
                        {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1, "children": []},
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
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "children": []},
                        {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1,
                         "children":
                             [{"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 1, "children": []},]
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
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1,
                         "children":
                            [{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2,
                              "children":
                                  [{"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 3,
                                    "children": []}, ]}]
                         },
                        {"pid": 4, "ppid": 4, "image": "blah", "command_line": "blah", "timestamp": 2, "children": []}
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
                        {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1,
                         "children":
                             [
                                 {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2,
                                  "children":
                                      [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "timestamp": 4, "children": []}]},
                                 {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 3, "children": []}
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
            ({"path": "blah", "name": "123_hollowshunter/hh_process_123_blah.shc", "description": "blah", "to_be_extracted": True}, "HollowsHunter Shellcode"),
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
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah"}], [{"pid": 1, "name": "blah", "score": 1}], {1: {"pid": 1, "ppid": 1, "process_name": "blah", "process_pid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "signatures": {"blah": 1}}}),
            ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah"}], [{"pid": 1, "name": "blah", "score": 1}], {1: {"pid": 1, "ppid": 1, "process_name": "blah", "process_pid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "signatures": {"blah": 1}}}),
        ]
    )
    def test_match_signatures_to_process_events(process_list, signatures, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        o = SandboxOntology(process_list)
        if process_list and signatures and process_list[0]["pid"] != signatures[0]["pid"]:
            o._match_signatures_to_process_events(signature_dicts=signatures)
            assert True
        else:
            actual_result = o._match_signatures_to_process_events(signature_dicts=signatures)
            assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("process_list, expected_result", [(None, []), ([], [])])
    def test_get_process_tree(process_list, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        o = SandboxOntology(process_list)
        actual_result = o.get_process_tree()
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("process_list, signatures, expected_result",
        [
            (None, [], []),
            ([], [], []),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah"}], [{"pid": 1, "name": "blah", "score": 1}], [{"children": [], "pid": 1, "ppid": 1, "process_name": "blah", "process_pid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "signatures": {"blah": 1}}]),
            ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah"}], [{"pid": 1, "name": "blah", "score": 1}], [{"children": [], "pid": 1, "ppid": 1, "process_name": "blah", "process_pid": 1, "image": "blah", "command_line": "blah", "timestamp": 1, "guid": "blah", "signatures": {"blah": 1}}]),
        ]
    )
    def test_get_process_tree_with_signatures(process_list, signatures, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        o = SandboxOntology(process_list)
        if process_list and signatures and process_list[0]["pid"] != signatures[0]["pid"]:
            o.get_process_tree_with_signatures(signatures=signatures)
            assert True
        else:
            actual_result = o.get_process_tree_with_signatures(signatures=signatures)
            assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("events, expected_result",
        [
            (None, []),
            ([], []),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah"}], [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah"}]),
            ([{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}], [{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}]),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah"}, {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}], [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah"}, {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}]),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah"}, {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 2.0, "guid": "blah"}], [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0, "guid": "blah"}, {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 2.0, "guid": "blah"}]),
            ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2.0, "guid": "blah"}, {"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}], [{"protocol": "blah", "src_ip": "blah", "src_port": 1, "domain": "blah", "dest_ip": "blah", "dest_port": 1, "pid": 1, "image": "blah", "timestamp": 1.0, "guid": "blah"}, {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 2.0, "guid": "blah"}]),
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

