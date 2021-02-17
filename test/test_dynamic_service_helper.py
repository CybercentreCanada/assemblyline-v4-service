import pytest
import os
from pathlib import Path

SERVICE_CONFIG_NAME = "service_manifest.yml"
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)


def check_process_equality(this, that):
    if this.pid == that.pid and this.ppid == that.ppid and this.image == that.image \
            and this.command_line == that.command_line and this.timestamp == that.timestamp:
        return True
    else:
        return False


def check_artefact_equality(this, that):
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
        open_manifest.write("name: Sample\nversion: sample\ndocker_config: \n  image: sample")


def teardown_module():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)


class TestProcess:
    @staticmethod
    @pytest.mark.parametrize("pid, ppid, image, command_line, timestamp",
        [
            (None, None, None, None, None),
            (1, 1, "blah", "blah", 1.0),
        ]
    )
    def test_init(pid, ppid, image, command_line, timestamp):
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        p = Process(pid=pid, ppid=ppid, image=image, command_line=command_line, timestamp=timestamp)
        assert p.pid == pid
        assert p.ppid == ppid
        assert p.image == image
        assert p.command_line == command_line
        assert p.timestamp == timestamp

    @staticmethod
    @pytest.mark.parametrize("pid, ppid, image, command_line, timestamp, expected_result",
        [
            (None, None, None, None, None,
                {"command_line": None, "image": None, "pid": None, "ppid": None, "timestamp": None}),
            (1, 1, "blah", "blah", 1.0,
                {"command_line": "blah", "image": "blah", "pid": 1, "ppid": 1, "timestamp": 1.0}),
        ]
    )
    def test_convert_process_to_dict(pid, ppid, image, command_line, timestamp, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        p = Process(pid=pid, ppid=ppid, image=image, command_line=command_line, timestamp=timestamp)
        actual_result = p.convert_process_to_dict()
        assert actual_result == expected_result


class TestArtefact:
    @staticmethod
    @pytest.mark.parametrize("name, path, description, to_be_extracted",
        [
            (None, None, None, None),
            ("blah", "blah", "blah", True),
            ("blah", "blah", "blah", False),
        ]
    )
    def test_init(name, path, description, to_be_extracted):
        from assemblyline_v4_service.common.dynamic_service_helper import Artefact
        if any(item is None for item in [name, path, description, to_be_extracted]):
            with pytest.raises(Exception):
                Artefact(name=name, path=path, description=description, to_be_extracted=to_be_extracted)
            return
        a = Artefact(name=name, path=path, description=description, to_be_extracted=to_be_extracted)
        assert a.name == name
        assert a.path == path
        assert a.description == description
        assert a.to_be_extracted == to_be_extracted


class TestOntology:
    @staticmethod
    @pytest.mark.parametrize("process_list, expected_process_list", [(None, []), ([], [])])
    def test_init(process_list, expected_process_list):
        from assemblyline_v4_service.common.dynamic_service_helper import Ontology
        o = Ontology(process_list=process_list)
        assert o.process_list == expected_process_list

    @staticmethod
    @pytest.mark.parametrize("process_list",
        [
            [],
            [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": "blah"}],
        ]
    )
    def test_validate_process_list(process_list):
        from assemblyline_v4_service.common.dynamic_service_helper import Ontology, Process
        actual_validated_process_list = Ontology._validate_process_list(process_list)
        for index, process in enumerate(process_list):
            expected_process = Process(
                pid=process["pid"],
                ppid=process["ppid"],
                image=process["image"],
                command_line=process["command_line"],
                timestamp=process["timestamp"],
            )
            assert check_process_equality(expected_process, actual_validated_process_list[index])

    @staticmethod
    @pytest.mark.parametrize("process_list, expected_result",
        [
            ([], {}),
            (
                [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": "blah"}],
                {1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": "blah"}}
            ),
        ]
    )
    def test_convert_processes_to_dict(process_list, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Ontology
        validated_process_list = Ontology(process_list)
        actual_result = validated_process_list._convert_processes_to_dict()
        assert actual_result == expected_result

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
        from assemblyline_v4_service.common.dynamic_service_helper import Ontology
        actual_result = Ontology._convert_processes_dict_to_tree(processes_dict)
        assert expected_result == actual_result

    @staticmethod
    @pytest.mark.parametrize("things_to_sort_by_timestamp, expected_result",
        [
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
    def test_sort_things_by_timestamp(things_to_sort_by_timestamp, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Ontology
        actual_result = Ontology._sort_things_by_timestamp(things_to_sort_by_timestamp)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("artefact_list",
        [
            None,
            [],
            [{"name": "blah", "path": "blah", "description": "blah", "to_be_extracted": True}],
        ]
    )
    def test_validate_artefacts(artefact_list):
        from assemblyline_v4_service.common.dynamic_service_helper import Ontology, Artefact
        actual_validated_artefact_list = Ontology._validate_artefacts(artefact_list)
        if artefact_list is None:
            artefact_list = []
        for index, artefact in enumerate(artefact_list):
            expected_artefact = Artefact(
                name=artefact["name"],
                path=artefact["path"],
                description=artefact["description"],
                to_be_extracted=artefact["to_be_extracted"]
            )
            assert check_artefact_equality(expected_artefact, actual_validated_artefact_list[index])

    @staticmethod
    @pytest.mark.parametrize("artefact, expected_result_section_title",
        [
            (None, None),
            ({"path": "blah", "name": "blah", "description": "blah", "to_be_extracted": True}, None),
            ({"path": "blah", "name": "hollowshunter/hh_process_123_blah.exe", "description": "blah", "to_be_extracted": True}, "HollowsHunter Injected Portable Executable"),
            ({"path": "blah", "name": "hollowshunter/hh_process_123_blah.shc", "description": "blah", "to_be_extracted": True}, "HollowsHunter Shellcode"),
            ({"path": "blah", "name": "hollowshunter/hh_process_123_blah.dll", "description": "blah", "to_be_extracted": True}, "HollowsHunter DLL"),
        ]
    )
    def test_handle_artefact(artefact, expected_result_section_title):
        from assemblyline_v4_service.common.dynamic_service_helper import Ontology, Artefact
        from assemblyline_v4_service.common.result import ResultSection

        if artefact is None:
            with pytest.raises(Exception):
                Ontology._handle_artefact(artefact, None)
            return

        expected_result_section = None
        if expected_result_section_title is not None:
            expected_result_section = ResultSection(expected_result_section_title)
            expected_result_section.add_tag("dynamic.process.file_name", artefact["path"])

        parent_result_section = ResultSection("blah")
        a = Artefact(
            name=artefact["name"],
            path=artefact["path"],
            description=artefact["description"],
            to_be_extracted=artefact["to_be_extracted"]
        )
        Ontology._handle_artefact(a, parent_result_section)
        if len(parent_result_section.subsections) > 0:
            actual_result_section = parent_result_section.subsections[0]
        else:
            actual_result_section = None

        if expected_result_section is None and actual_result_section is None:
            assert True
        else:
            assert check_section_equality(actual_result_section, expected_result_section)

    @staticmethod
    @pytest.mark.parametrize("process_list, expected_result", [(None, []), ([], [])])
    def test_get_process_tree(process_list, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Ontology
        o = Ontology(process_list)
        actual_result = o.get_process_tree()
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize("processes, network_calls, expected_result",
        [
            (None, None, []),
            ([], [], []),
            ([{"pid": 1, "timestamp": 1}], [], [{"pid": 1, "timestamp": 1}]),
            ([], [{"domain": "blah", "timestamp": 1}], [{"domain": "blah", "timestamp": 1}]),
            ([{"pid": 1, "timestamp": 1}], [{"domain": "blah", "timestamp": 1}], [{"pid": 1, "timestamp": 1}, {"domain": "blah", "timestamp": 1}]),
            ([{"pid": 1, "timestamp": 1}], [{"domain": "blah", "timestamp": 2}], [{"pid": 1, "timestamp": 1}, {"domain": "blah", "timestamp": 2}]),
            ([{"pid": 1, "timestamp": 2}], [{"domain": "blah", "timestamp": 1}], [{"domain": "blah", "timestamp": 1}, {"pid": 1, "timestamp": 2}]),
        ]
    )
    def test_get_events(processes, network_calls, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Ontology
        actual_result = Ontology.get_events(processes, network_calls)
        assert actual_result == expected_result

    # TODO: implement this
    # @staticmethod
    # def test_run_signatures():
    #     from assemblyline_v4_service.common.dynamic_service_helper import Ontology
    #     o = Ontology()
    #     actual_result = o.run_signatures()
    #     assert actual_result is True

    @staticmethod
    @pytest.mark.parametrize("artefact_list, expected_result",
        [
            (None, None),
            ([], None),
            ([{"name": "blah", "path": "blah", "description": "blah", "to_be_extracted": True}], None),
            ([{"name": "blah", "path": "blah", "description": "blah", "to_be_extracted": False}], None),
        ]
    )
    def test_handle_artefacts(artefact_list, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Ontology
        o = Ontology()
        actual_result = o.handle_artefacts(artefact_list)
        assert actual_result == expected_result

