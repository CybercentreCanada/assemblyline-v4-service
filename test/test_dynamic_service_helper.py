import pytest
import os

SERVICE_CONFIG_NAME = "service_manifest.yml"
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)


def setup_module():
    if not os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        open_manifest = open(TEMP_SERVICE_CONFIG_PATH, "w")
        open_manifest.write(
            "name: Sample\nversion: sample\ndocker_config: \n  image: sample\nheuristics:\n  - heur_id: 17\n"
            "    name: blah\n    description: blah\n    filetype: '*'\n    score: 250"
        )


def teardown_module():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        result_heuristic_equality = (
            this.heuristic.attack_ids == that.heuristic.attack_ids
            and this.heuristic.frequency == that.heuristic.frequency
            and this.heuristic.heur_id == that.heuristic.heur_id
            and this.heuristic.score == that.heuristic.score
            and this.heuristic.score_map == that.heuristic.score_map
            and this.heuristic.signatures == that.heuristic.signatures
        )

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = (
        result_heuristic_equality
        and this.body == that.body
        and this.body_format == that.body_format
        and this.classification == that.classification
        and this.depth == that.depth
        and len(this.subsections) == len(that.subsections)
        and this.title_text == that.title_text
    )

    if not current_section_equality:
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(
            subsection, that.subsections[index]
        )
        if not subsection_equality:
            return False

    return True


@pytest.fixture
def dummy_object_class():
    class DummyObject:
        def __init__(self, id=None) -> None:
            self.id = id

    yield DummyObject


@pytest.fixture
def dummy_timestamp_class():
    class DummyEvent:
        class DummyObjectID:
            def __init__(self, item):
                self.time_observed = item.get("time_observed")
                self.guid = item.get("guid")

        def __init__(self, item):
            self.objectid = self.DummyObjectID(item.get("objectid", {}))
            self.pobjectid = self.DummyObjectID(item.get("pobjectid", {}))

    yield DummyEvent


@pytest.fixture
def dummy_task_class():
    class DummyTask:
        def __init__(self):
            self.supplementary = []
            self.extracted = []

    yield DummyTask


@pytest.fixture
def dummy_request_class(dummy_task_class):
    class DummyRequest(dict):
        def __init__(self):
            super(DummyRequest, self).__init__()
            self.task = dummy_task_class()

        def add_supplementary(self, path, name, description):
            self.task.supplementary.append(
                {"path": path, "name": name, "description": description}
            )

        def add_extracted(self, path, name, description):
            self.task.extracted.append(
                {"path": path, "name": name, "description": description}
            )

    yield DummyRequest


class TestModule:
    @staticmethod
    def test_update_object_items(dummy_object_class):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            update_object_items,
        )

        dummy = dummy_object_class()
        update_object_items(
            dummy, {"id": "blah", "something": "blah", "blah": None, "blahblah": ""}
        )
        assert dummy.id == "blah"
        assert dummy.__dict__ == {"id": "blah"}
        assert update_object_items(dummy, {"id": None}) is None


class TestArtifact:
    @staticmethod
    @pytest.mark.parametrize(
        "name, path, description, to_be_extracted",
        [
            (None, None, None, None),
            ("blah", "blah", "blah", True),
            ("blah", "blah", "blah", False),
        ],
    )
    def test_artifact_init(name, path, description, to_be_extracted):
        from assemblyline_v4_service.common.dynamic_service_helper import Artifact

        if any(item is None for item in [name, path, description, to_be_extracted]):
            with pytest.raises(Exception):
                Artifact(
                    name=name,
                    path=path,
                    description=description,
                    to_be_extracted=to_be_extracted,
                )
            return
        a = Artifact(
            name=name,
            path=path,
            description=description,
            to_be_extracted=to_be_extracted,
        )
        assert a.name == name
        assert a.path == path
        assert a.description == description
        assert a.to_be_extracted == to_be_extracted

    @staticmethod
    def test_artifact_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import Artifact

        a = Artifact(
            name="blah", path="blah", description="blah", to_be_extracted="blah"
        )
        assert a.as_primitives() == {
            "name": "blah",
            "path": "blah",
            "description": "blah",
            "to_be_extracted": "blah",
        }


class TestObjectID:
    @staticmethod
    def test_objectid_init():
        from assemblyline_v4_service.common.dynamic_service_helper import ObjectID

        default_oid = ObjectID()
        assert default_oid.guid is None
        assert default_oid.tag is None
        assert default_oid.treeid is None
        assert default_oid.processtree is None
        assert default_oid.time_observed is None

        set_oid = ObjectID(
            guid="{12345678-1234-5678-1234-567812345678}",
            tag="blah",
            treeid="blah",
            processtree="blah",
            time_observed=1.0,
        )

        assert set_oid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert set_oid.tag == "blah"
        assert set_oid.treeid == "blah"
        assert set_oid.processtree == "blah"
        assert set_oid.time_observed == 1.0

        with pytest.raises(ValueError):
            ObjectID(guid="blah")

    @staticmethod
    def test_objectid_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import ObjectID

        default_oid = ObjectID()
        assert default_oid.as_primitives() == {
            "guid": None,
            "tag": None,
            "treeid": None,
            "processtree": None,
            "time_observed": None,
        }

    @staticmethod
    def test_objectid_assign_guid():
        from assemblyline_v4_service.common.dynamic_service_helper import ObjectID
        from uuid import UUID

        oid = ObjectID()
        oid.assign_guid()
        assert str(UUID(oid.guid))

    @staticmethod
    def test_set_tag():
        from assemblyline_v4_service.common.dynamic_service_helper import ObjectID

        oid = ObjectID()
        oid.set_tag("blah")
        assert oid.tag == "blah"

        oid.set_tag(None)
        assert oid.tag == "blah"

        oid.set_tag("")
        assert oid.tag == "blah"

        oid.set_tag(1.0)
        assert oid.tag == "blah"

    @staticmethod
    def test_set_time_observed():
        from assemblyline_v4_service.common.dynamic_service_helper import ObjectID

        oid = ObjectID()
        oid.set_time_observed(1)
        assert oid.time_observed == 1.0

        oid.set_time_observed(None)
        assert oid.time_observed == 1.0

        oid.set_time_observed("blah")
        assert oid.time_observed == 1.0

        oid.set_time_observed(1.0)
        assert oid.time_observed == 1.0


class TestProcess:
    @staticmethod
    def test_process_init():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            Process,
            ObjectID,
        )

        default_p = Process()
        assert default_p.objectid.guid is None
        assert default_p.objectid.tag is None
        assert default_p.objectid.treeid is None
        assert default_p.objectid.processtree is None
        assert default_p.objectid.time_observed is None
        assert default_p.pobjectid.guid is None
        assert default_p.pobjectid.tag is None
        assert default_p.pobjectid.treeid is None
        assert default_p.pobjectid.processtree is None
        assert default_p.pobjectid.time_observed is None
        assert default_p.pimage is None
        assert default_p.pcommand_line is None
        assert default_p.ppid is None
        assert default_p.pid is None
        assert default_p.image is None
        assert default_p.command_line is None
        assert default_p.start_time is None
        assert default_p.end_time is None

        # Without objectids
        set_p1 = Process(
            guid="{12345678-1234-5678-1234-567812345678}",
            tag="blah",
            treeid="blah",
            processtree="blah",
            pguid="{12345678-1234-5678-1234-567812345679}",
            ptag="blah",
            ptreeid="blah",
            pprocesstree="blah",
            pimage="C:\\Windows\\System32\\cmd.exe",
            pcommand_line="C:\\Windows\\System32\\cmd.exe -m bad.exe",
            ppid=123,
            pid=123,
            image="C:\\Windows\\System32\\cmd.exe",
            command_line="C:\\Windows\\System32\\cmd.exe -m bad.exe",
            start_time=1.0,
            end_time=1.0,
        )

        assert set_p1.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert set_p1.objectid.tag == "?sys32\\cmd.exe"
        assert set_p1.objectid.treeid == "blah"
        assert set_p1.objectid.processtree == "blah"
        assert set_p1.objectid.time_observed == 1.0
        assert set_p1.pobjectid.guid == "{12345678-1234-5678-1234-567812345679}"
        assert set_p1.pobjectid.tag == "?sys32\\cmd.exe"
        assert set_p1.pobjectid.treeid == "blah"
        assert set_p1.pobjectid.processtree == "blah"
        assert set_p1.pobjectid.time_observed is None
        assert set_p1.pimage == "C:\\Windows\\System32\\cmd.exe"
        assert set_p1.pcommand_line == "C:\\Windows\\System32\\cmd.exe -m bad.exe"
        assert set_p1.ppid == 123
        assert set_p1.pid == 123
        assert set_p1.image == "C:\\Windows\\System32\\cmd.exe"
        assert set_p1.command_line == "C:\\Windows\\System32\\cmd.exe -m bad.exe"
        assert set_p1.start_time == 1.0
        assert set_p1.end_time == 1.0

        objectid = ObjectID(
            guid="{12345678-1234-5678-1234-567812345678}",
            tag="blah",
            treeid="blah",
            processtree="blah",
            time_observed=1.0,
        )

        pobjectid = ObjectID(
            guid="{12345678-1234-5678-1234-567812345679}",
            tag="blah",
            treeid="blah",
            processtree="blah",
            time_observed=1.0,
        )

        # With objectids
        set_p2 = Process(
            guid="{12345678-1234-5678-1234-567812345671}",
            tag="blah1",
            treeid="blah1",
            processtree="blah1",
            pguid="{12345678-1234-5678-1234-567812345672}",
            ptag="blah1",
            ptreeid="blah1",
            pprocesstree="blah1",
            pimage="C:\\Windows\\System32\\cmd.exe",
            pcommand_line="C:\\Windows\\System32\\cmd.exe -m bad.exe",
            ppid=123,
            pid=123,
            image="C:\\Windows\\System32\\cmd.exe",
            command_line="C:\\Windows\\System32\\cmd.exe -m bad.exe",
            start_time=1.0,
            end_time=1.0,
            objectid=objectid,
            pobjectid=pobjectid,
        )

        assert set_p2.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert set_p2.objectid.tag == "blah"
        assert set_p2.objectid.treeid == "blah"
        assert set_p2.objectid.processtree == "blah"
        assert set_p2.objectid.time_observed == 1.0
        assert set_p2.pobjectid.guid == "{12345678-1234-5678-1234-567812345679}"
        assert set_p2.pobjectid.tag == "blah"
        assert set_p2.pobjectid.treeid == "blah"
        assert set_p2.pobjectid.processtree == "blah"
        assert set_p2.pobjectid.time_observed == 1.0
        assert set_p2.pimage == "C:\\Windows\\System32\\cmd.exe"
        assert set_p2.pcommand_line == "C:\\Windows\\System32\\cmd.exe -m bad.exe"
        assert set_p2.ppid == 123
        assert set_p2.pid == 123
        assert set_p2.image == "C:\\Windows\\System32\\cmd.exe"
        assert set_p2.command_line == "C:\\Windows\\System32\\cmd.exe -m bad.exe"
        assert set_p2.start_time == 1.0
        assert set_p2.end_time == 1.0

        with pytest.raises(ValueError):
            Process(pid="a")

        with pytest.raises(ValueError):
            Process(start_time=2.0, end_time=1.0)

    @staticmethod
    def test_process_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        p = Process()
        assert p.as_primitives() == {
            "objectid": {
                "guid": None,
                "tag": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
            },
            "pobjectid": {
                "guid": None,
                "tag": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
            },
            "pimage": None,
            "pcommand_line": None,
            "ppid": None,
            "pid": None,
            "image": None,
            "command_line": None,
            "start_time": None,
            "end_time": None,
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
        }

    @staticmethod
    def test_process_update():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        p = Process(image="blah")

        p.update(image=None)
        assert p.image == "blah"

        p.update(
            objectid={
                "guid": "{12345678-1234-5678-1234-567812345679}",
                "tag": "blah",
                "treeid": "blah",
                "processtree": "blah",
                "time_observed": 1,
            }
        )
        assert p.objectid.guid == "{12345678-1234-5678-1234-567812345679}"
        assert p.objectid.tag == "blah"
        assert p.objectid.treeid == "blah"
        assert p.objectid.processtree == "blah"
        assert p.objectid.time_observed == 1

        p = Process()
        p.update(
            guid="{12345678-1234-5678-1234-567812345678}",
            tag="blah2",
            treeid="blah2",
            processtree="blah2",
            time_observed=2,
        )
        assert p.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert p.objectid.tag == "blah2"
        assert p.objectid.treeid == "blah2"
        assert p.objectid.processtree == "blah2"
        assert p.objectid.time_observed == 2

        p.update(image="C:\\program files\\blah")
        assert p.image == "C:\\program files\\blah"
        assert p.objectid.tag == "?pf86\\blah"

        p.update(
            pobjectid={
                "guid": "{12345678-1234-5678-1234-567812345679}",
                "tag": "blah",
                "treeid": "blah",
                "processtree": "blah",
                "time_observed": 1,
            }
        )
        assert p.pobjectid.guid == "{12345678-1234-5678-1234-567812345679}"
        assert p.pobjectid.tag == "blah"
        assert p.pobjectid.treeid == "blah"
        assert p.pobjectid.processtree == "blah"
        assert p.pobjectid.time_observed == 1

        p = Process()
        p.update(
            pguid="{12345678-1234-5678-1234-567812345678}",
            ptag="blah2",
            ptreeid="blah2",
            pprocesstree="blah2",
            ptime_observed=2,
        )
        assert p.pobjectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert p.pobjectid.tag == "blah2"
        assert p.pobjectid.treeid == "blah2"
        assert p.pobjectid.processtree == "blah2"
        assert p.pobjectid.time_observed == 2

        p.update(pimage="C:\\program files\\blah")
        assert p.pimage == "C:\\program files\\blah"
        assert p.pobjectid.tag == "?pf86\\blah"

        p.update(integrity_level="BLAH")
        assert p.integrity_level == "blah"

    @staticmethod
    def test_set_parent():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        child_p1 = Process()
        parent_p1 = Process(
            guid="{12345678-1234-5678-1234-567812345678}",
            image="blah",
            command_line="blah",
            pid=123,
            tag="blah",
            treeid="blah",
            processtree="blah",
            start_time=1.0,
        )
        child_p1.set_parent(parent_p1)

        assert child_p1.pobjectid.guid == parent_p1.objectid.guid
        assert child_p1.pobjectid.tag == parent_p1.objectid.tag
        assert child_p1.pobjectid.treeid == parent_p1.objectid.treeid
        assert child_p1.pobjectid.processtree == parent_p1.objectid.processtree
        assert child_p1.pobjectid.time_observed == parent_p1.objectid.time_observed
        assert child_p1.pimage == parent_p1.image
        assert child_p1.pcommand_line == parent_p1.command_line
        assert child_p1.ppid == parent_p1.pid

        child_p2 = Process(pcommand_line="blah")
        parent_p2 = Process(
            guid="{12345678-1234-5678-1234-567812345678}",
            image="blah",
            pid=123,
            tag="blah",
            treeid="blah",
            processtree="blah",
            start_time=1.0,
        )
        child_p2.set_parent(parent_p2)

        assert child_p2.pobjectid.guid == parent_p2.objectid.guid
        assert child_p2.pobjectid.tag == parent_p2.objectid.tag
        assert child_p2.pobjectid.treeid == parent_p2.objectid.treeid
        assert child_p2.pobjectid.processtree == parent_p2.objectid.processtree
        assert child_p2.pobjectid.time_observed == parent_p2.objectid.time_observed
        assert child_p2.pimage == parent_p2.image
        assert child_p2.pcommand_line == "blah"
        assert child_p2.ppid == parent_p2.pid

    @staticmethod
    def test_set_start_time():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        p = Process()
        p.set_start_time(1.0)
        assert p.start_time == 1.0

    @staticmethod
    def test_set_end_time():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        p = Process()
        p.set_end_time(1.0)
        assert p.end_time == 1.0

    @staticmethod
    def test_is_guid_a_match():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        p = Process(guid="{12345678-1234-5678-1234-567812345678}")
        assert p.is_guid_a_match("{12345678-1234-5678-1234-567812345678}")
        assert not p.is_guid_a_match("{12345678-1234-5678-1234-567812345670}")

    @staticmethod
    def test_set_objectid_tag():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        p = Process()
        p.set_objectid_tag("C:\\program files\\blah")
        assert p.objectid.tag == "?pf86\\blah"

    @staticmethod
    def test_set_pobjectid_tag():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        p = Process()
        p.set_pobjectid_tag("C:\\program files\\blah")
        assert p.pobjectid.tag == "?pf86\\blah"

    @staticmethod
    def test_process_update_objectid():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        p = Process()
        p.update_objectid()
        assert p.objectid.guid is None
        assert p.objectid.tag is None
        assert p.objectid.treeid is None
        assert p.objectid.processtree is None
        assert p.objectid.time_observed is None

        p.update_objectid(
            guid="{12345678-1234-5678-1234-567812345678}",
            tag="blah",
            treeid="blah",
            processtree="blah",
            time_observed=1.0,
        )
        assert p.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert p.objectid.tag == "blah"
        assert p.objectid.treeid == "blah"
        assert p.objectid.processtree == "blah"
        assert p.objectid.time_observed == 1.0

    @staticmethod
    def test_process_update_pobjectid():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        p = Process()
        p.update_pobjectid()
        assert p.pobjectid.guid is None
        assert p.pobjectid.tag is None
        assert p.pobjectid.treeid is None
        assert p.pobjectid.processtree is None
        assert p.pobjectid.time_observed is None

        p.update_pobjectid(
            guid="{12345678-1234-5678-1234-567812345678}",
            tag="blah",
            treeid="blah",
            processtree="blah",
            time_observed=1.0,
        )
        assert p.pobjectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert p.pobjectid.tag == "blah"
        assert p.pobjectid.treeid == "blah"
        assert p.pobjectid.processtree == "blah"
        assert p.pobjectid.time_observed == 1.0

    @staticmethod
    @pytest.mark.parametrize(
        "path, expected_result",
        [
            ("blah", "x86"),
            ("C:\\program files\\blah", "x86"),
            ("C:\\program files (x86)\\blah", "x86_64"),
            ("C:\\syswow64\\blah", "x86_64"),
        ],
    )
    def test_determine_arch(path, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        p = Process(image=path)
        actual_result = p._determine_arch(path)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "path, rule, expected_result",
        [
            ("blah", {"pattern": "", "replacement": ""}, "blah"),
            ("blah", {"pattern": "ah", "replacement": "ue"}, "blah"),
            ("blah", {"pattern": "bl", "replacement": "y"}, "yah"),
        ],
    )
    def test_pattern_substitution(path, rule, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        actual_result = Process._pattern_substitution(path, rule)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "path, rule, expected_result",
        [
            ("blah", {"regex": "", "replacement": ""}, "blah"),
            ("blah", {"regex": "bl*ah", "replacement": "bl"}, "blah"),
            ("blah", {"regex": "\\bl*ah", "replacement": "bl"}, "blah"),
            ("blaah", {"regex": "bl*ah", "replacement": "blue"}, "blue"),
        ],
    )
    def test_regex_substitution(path, rule, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        actual_result = Process._regex_substitution(path, rule)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "path, arch, expected_result",
        [
            ("blah", None, "blah"),
            ("C:\\Program Files\\Word.exe", None, "?pf86\\word.exe"),
            ("C:\\Program Files (x86)\\Word.exe", None, "?pf86\\word.exe"),
            ("C:\\Program Files (x86)\\Word.exe", "x86_64", "?pf86\\word.exe"),
            ("C:\\Windows\\System32\\Word.exe", None, "?sys32\\word.exe"),
            ("C:\\Windows\\SysWow64\\Word.exe", None, "?sys32\\word.exe"),
            ("C:\\Windows\\SysWow64\\Word.exe", "x86", "?win\\syswow64\\word.exe"),
            ("C:\\Windows\\SysWow64\\Word.exe", "x86_64", "?sys32\\word.exe"),
            (
                "C:\\Users\\buddy\\AppData\\Local\\Temp\\Word.exe",
                None,
                "?usrtmp\\word.exe",
            ),
            ("C:\\Users\\buddy\\Word.exe", None, "?usr\\word.exe"),
        ],
    )
    def test_normalize_path(path, arch, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        actual_result = Process._normalize_path(path, arch)
        assert actual_result == expected_result


class TestNetworkConnection:
    @staticmethod
    def test_network_connection_init():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkConnection,
            Process,
            ObjectID,
        )
        from uuid import UUID

        default_nc = NetworkConnection()
        assert default_nc.process is None
        assert default_nc.source_ip is None
        assert default_nc.source_port is None
        assert default_nc.destination_ip is None
        assert default_nc.destination_port is None
        assert default_nc.transport_layer_protocol is None
        assert default_nc.direction is None
        assert str(UUID(default_nc.objectid.guid))
        assert default_nc.objectid.treeid is None
        assert default_nc.objectid.processtree is None
        assert default_nc.objectid.tag is None
        assert default_nc.objectid.time_observed is None

        with pytest.raises(ValueError):
            NetworkConnection(
                transport_layer_protocol="blah",
            )

        with pytest.raises(ValueError):
            NetworkConnection(
                direction="blah",
            )

        # Without objectid
        set_nc1 = NetworkConnection(
            guid="{12345678-1234-5678-1234-567812345678}",
            tag="blah",
            treeid="blah",
            processtree="blah",
            time_observed=1.0,
            source_ip="blah",
            source_port=123,
            destination_ip="blah",
            destination_port=123,
            transport_layer_protocol="tcp",
            direction="outbound",
        )

        assert set_nc1.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert set_nc1.objectid.tag == "blah"
        assert set_nc1.objectid.treeid == "blah"
        assert set_nc1.objectid.processtree == "blah"
        assert set_nc1.objectid.time_observed == 1.0
        assert set_nc1.source_ip == "blah"
        assert set_nc1.source_port == 123
        assert set_nc1.destination_ip == "blah"
        assert set_nc1.destination_port == 123
        assert set_nc1.transport_layer_protocol == "tcp"
        assert set_nc1.direction == "outbound"

        oid = ObjectID(
            guid="{12345678-1234-5678-1234-567812345678}",
            tag="blah",
            treeid="blah",
            processtree="blah",
            time_observed=1.0,
        )

        # With objectid
        set_nc2 = NetworkConnection(
            guid="{12345678-1234-5678-1234-567812345671}",
            tag="blah1",
            treeid="blah1",
            processtree="blah1",
            time_observed=1.01,
            source_ip="blah",
            source_port=123,
            destination_ip="blah",
            destination_port=123,
            transport_layer_protocol="tcp",
            direction="outbound",
            objectid=oid,
        )

        assert set_nc2.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert set_nc2.objectid.tag == "blah"
        assert set_nc2.objectid.treeid == "blah"
        assert set_nc2.objectid.processtree == "blah"
        assert set_nc2.objectid.time_observed == 1.0
        assert set_nc2.source_ip == "blah"
        assert set_nc2.source_port == 123
        assert set_nc2.destination_ip == "blah"
        assert set_nc2.destination_port == 123
        assert set_nc2.transport_layer_protocol == "tcp"
        assert set_nc2.direction == "outbound"

        p = Process(image="C:\\Windows\\System32\\cmd.exe")
        nc_w_p = NetworkConnection(process=p)
        assert nc_w_p.process.image == "C:\\Windows\\System32\\cmd.exe"
        assert nc_w_p.process.objectid.tag == "?sys32\\cmd.exe"

    @staticmethod
    def test_network_connection_update_objectid():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkConnection,
        )
        from uuid import UUID

        nc = NetworkConnection()
        nc.update_objectid()

        assert str(UUID(nc.objectid.guid))
        assert nc.objectid.tag is None
        assert nc.objectid.treeid is None
        assert nc.objectid.processtree is None
        assert nc.objectid.time_observed is None

        nc.update_objectid(
            tag="blah",
            treeid="blah",
            processtree="blah",
            time_observed=1.0,
        )
        assert nc.objectid.tag == "blah"
        assert nc.objectid.treeid == "blah"
        assert nc.objectid.processtree == "blah"
        assert nc.objectid.time_observed == 1.0

    @staticmethod
    def test_network_connection_update():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkConnection,
        )

        nc = NetworkConnection(destination_ip="blah")

        nc.update(destination_ip=None)
        assert nc.destination_ip == "blah"

        nc.update(
            objectid={
                "tag": "blah",
                "treeid": "blah",
                "processtree": "blah",
                "time_observed": 1,
            }
        )
        assert nc.objectid.tag == "blah"
        assert nc.objectid.treeid == "blah"
        assert nc.objectid.processtree == "blah"
        assert nc.objectid.time_observed == 1

        nc = NetworkConnection(destination_ip="blah")
        nc.update(
            tag="blah2",
            treeid="blah2",
            processtree="blah2",
            time_observed=2,
        )
        assert nc.objectid.tag == "blah2"
        assert nc.objectid.treeid == "blah2"
        assert nc.objectid.processtree == "blah2"
        assert nc.objectid.time_observed == 2

        nc = NetworkConnection()
        nc.update(destination_ip="blahblah")
        assert nc.destination_ip == "blahblah"

        nc.update(process={})
        assert nc.process is None

        nc.update(process={"tag": "blah"})
        assert nc.process.objectid.tag == "blah"

    @staticmethod
    def test_network_connection_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkConnection,
        )

        default_nc = NetworkConnection()
        default_nc.update_process(
            pid=123,
            invalid="blah",
            image="C:\\Windows\\System32\\cmd.exe",
            pimage="C:\\Windows\\System32\\cmd.exe",
            integrity_level="BLAH",
        )
        assert default_nc.process.pid == 123
        assert default_nc.process.image == "C:\\Windows\\System32\\cmd.exe"
        assert default_nc.process.objectid.tag == "?sys32\\cmd.exe"
        assert default_nc.process.pobjectid.tag == "?sys32\\cmd.exe"
        assert default_nc.process.integrity_level == "blah"
        default_nc.update_process(image=None)
        assert default_nc.process.image == "C:\\Windows\\System32\\cmd.exe"

    @staticmethod
    def test_network_connection_update_process_objectid():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkConnection,
        )
        from uuid import UUID

        nc = NetworkConnection()
        nc.update_process_objectid()

        assert str(UUID(nc.objectid.guid))
        assert nc.objectid.tag is None
        assert nc.objectid.treeid is None
        assert nc.objectid.processtree is None
        assert nc.objectid.time_observed is None

        nc.update_process_objectid(
            guid="{12345678-1234-5678-1234-567812345678}",
            tag="blah",
            treeid="blah",
            processtree="blah",
            time_observed=1.0,
        )
        assert nc.process.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert nc.process.objectid.tag == "blah"
        assert nc.process.objectid.treeid == "blah"
        assert nc.process.objectid.processtree == "blah"
        assert nc.process.objectid.time_observed == 1.0

    @staticmethod
    def test_network_connection_set_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkConnection,
            Process,
        )

        default_nc = NetworkConnection()
        p1 = Process(pid=1)
        default_nc.set_process(p1)
        assert default_nc.process.pid == 1

    @staticmethod
    def test_create_tag():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkConnection,
        )

        default_nc = NetworkConnection()

        # destination ip is None
        default_nc.create_tag()
        assert default_nc.objectid.tag is None

        # destination port is None
        default_nc.create_tag("blah.com")
        assert default_nc.objectid.tag is None

        default_nc.update(destination_ip="1.1.1.1", destination_port=123)
        default_nc.create_tag()
        assert default_nc.objectid.tag == "1.1.1.1:123"

        default_nc.create_tag("blah.com")
        assert default_nc.objectid.tag == "1.1.1.1:123"

        default_nc = NetworkConnection()
        default_nc.update(direction="outbound", destination_ip="1.1.1.1", destination_port=123)
        default_nc.create_tag("blah.com")
        assert default_nc.objectid.tag == "blah.com:123"

    @staticmethod
    def test_network_connection_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkConnection,
        )
        from uuid import UUID

        default_nc = NetworkConnection()
        default_nc_as_primitives = default_nc.as_primitives()
        assert str(UUID(default_nc_as_primitives["objectid"].pop("guid")))
        assert default_nc_as_primitives == {
            "objectid": {
                "tag": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
            },
            "process": None,
            "source_ip": None,
            "source_port": None,
            "destination_ip": None,
            "destination_port": None,
            "transport_layer_protocol": None,
            "direction": None,
        }


class TestNetworkDNS:
    @staticmethod
    def test_network_dns_init():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkDNS
        from uuid import UUID

        default_nd = NetworkDNS()

        assert default_nd.connection_details.process is None
        assert default_nd.connection_details.source_ip is None
        assert default_nd.connection_details.source_port is None
        assert default_nd.connection_details.destination_ip is None
        assert default_nd.connection_details.destination_port is None
        assert default_nd.connection_details.transport_layer_protocol is None
        assert default_nd.connection_details.direction is None
        assert str(UUID(default_nd.connection_details.objectid.guid))
        assert default_nd.connection_details.objectid.tag is None
        assert default_nd.connection_details.objectid.treeid is None
        assert default_nd.connection_details.objectid.processtree is None
        assert default_nd.connection_details.objectid.time_observed is None
        assert default_nd.domain is None
        assert default_nd.resolved_ips == []
        assert default_nd.lookup_type is None

        set_nd = NetworkDNS(domain="blah", resolved_ips=["blah"], lookup_type="A")

        assert set_nd.domain == "blah"
        assert set_nd.resolved_ips == ["blah"]
        assert set_nd.lookup_type == "A"

    @staticmethod
    def test_network_dns_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkDNS

        default_nd = NetworkDNS()
        default_nd.update_process(
            pid=123,
            invalid="blah",
            image="C:\\Windows\\System32\\cmd.exe",
            pimage="C:\\Windows\\System32\\cmd.exe",
            integrity_level="BLAH",
        )
        assert default_nd.connection_details.process.pid == 123
        assert (
            default_nd.connection_details.process.image
            == "C:\\Windows\\System32\\cmd.exe"
        )
        assert (
            default_nd.connection_details.process.pimage
            == "C:\\Windows\\System32\\cmd.exe"
        )
        assert default_nd.connection_details.process.objectid.tag == "?sys32\\cmd.exe"
        assert default_nd.connection_details.process.pobjectid.tag == "?sys32\\cmd.exe"
        assert default_nd.connection_details.process.integrity_level == "blah"

        default_nd.update_process(image=None)
        assert (
            default_nd.connection_details.process.image
            == "C:\\Windows\\System32\\cmd.exe"
        )

    @staticmethod
    def test_network_dns_set_network_connection():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkDNS,
            NetworkConnection,
        )

        default_nd = NetworkDNS(domain="blah")
        default_nc = NetworkConnection(destination_ip="1.1.1.1")
        default_nd.set_network_connection(default_nc)
        assert default_nd.connection_details.destination_ip == "1.1.1.1"

    @staticmethod
    def test_network_dns_update_connection_details():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkDNS

        default_nd = NetworkDNS()
        default_nd.update_connection_details(destination_ip="blah", invalid="blah")
        assert default_nd.connection_details.destination_ip == "blah"

    @staticmethod
    def test_network_dns_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkDNS
        from uuid import UUID

        default_nd = NetworkDNS()
        default_nd_as_primitives = default_nd.as_primitives()
        assert str(
            UUID(default_nd_as_primitives["connection_details"]["objectid"].pop("guid"))
        )
        assert default_nd_as_primitives == {
            "connection_details": {
                "objectid": {
                    "tag": None,
                    "treeid": None,
                    "processtree": None,
                    "time_observed": None,
                },
                "process": None,
                "source_ip": None,
                "source_port": None,
                "destination_ip": None,
                "destination_port": None,
                "transport_layer_protocol": None,
                "direction": None,
            },
            "domain": None,
            "resolved_ips": [],
            "lookup_type": None,
        }


class TestNetworkHTTP:
    @staticmethod
    def test_network_http_init():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP
        from uuid import UUID

        default_nh = NetworkHTTP()
        assert default_nh.connection_details.process is None
        assert default_nh.connection_details.source_ip is None
        assert default_nh.connection_details.source_port is None
        assert default_nh.connection_details.destination_ip is None
        assert default_nh.connection_details.destination_port is None
        assert default_nh.connection_details.transport_layer_protocol is None
        assert default_nh.connection_details.direction is None
        assert str(UUID(default_nh.connection_details.objectid.guid))
        assert default_nh.connection_details.objectid.tag is None
        assert default_nh.connection_details.objectid.treeid is None
        assert default_nh.connection_details.objectid.processtree is None
        assert default_nh.connection_details.objectid.time_observed is None
        assert default_nh.request_uri is None
        assert default_nh.request_headers == {}
        assert default_nh.request_method is None
        assert default_nh.response_status_code is None
        assert default_nh.response_body is None
        assert default_nh.response_body_path is None
        assert default_nh.request_body_path is None

        set_nh = NetworkHTTP(
            request_uri="blah",
            request_headers={"a": "b"},
            request_body="blah",
            request_method="blah",
            response_headers={"a": "b"},
            response_status_code=123,
            response_body="blah",
            response_body_path="blah",
            request_body_path="blah",
        )

        assert set_nh.request_uri == "blah"
        assert set_nh.request_headers == {"a": "b"}
        assert set_nh.request_body == "blah"
        assert set_nh.request_method == "blah"
        assert set_nh.response_headers == {"a": "b"}
        assert set_nh.response_status_code == 123
        assert set_nh.response_body == "blah"
        assert set_nh.response_body_path == "blah"
        assert set_nh.request_body_path == "blah"

    @staticmethod
    def test_network_http_update():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkHTTP,
        )

        nh = NetworkHTTP()

        nh.update(request_uri="blah")
        assert nh.request_uri == "blah"

        nh.update(request_uri=None)
        assert nh.request_uri == "blah"

        nh.update(
            process={
                "guid": "{12345678-1234-5678-1234-567812345679}",
            }
        )
        assert nh.connection_details.process.objectid.guid == "{12345678-1234-5678-1234-567812345679}"

        nh.update(process={})
        assert nh.connection_details.process.objectid.guid == "{12345678-1234-5678-1234-567812345679}"

        nh.update(
            connection_details={
                "destination_ip": "1.1.1.1"
            }
        )
        assert nh.connection_details.destination_ip == "1.1.1.1"

        nh.update(connection_details={})
        assert nh.connection_details.destination_ip == "1.1.1.1"

    @staticmethod
    def test_network_http_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP

        default_nh = NetworkHTTP()
        default_nh.update_process(
            pid=123,
            invalid="blah",
            image="C:\\Windows\\System32\\cmd.exe",
            pimage="C:\\Windows\\System32\\cmd.exe",
            integrity_level="BLAH",
        )
        assert default_nh.connection_details.process.pid == 123
        assert (
            default_nh.connection_details.process.image
            == "C:\\Windows\\System32\\cmd.exe"
        )
        assert (
            default_nh.connection_details.process.pimage
            == "C:\\Windows\\System32\\cmd.exe"
        )
        assert default_nh.connection_details.process.objectid.tag == "?sys32\\cmd.exe"
        assert default_nh.connection_details.process.pobjectid.tag == "?sys32\\cmd.exe"
        assert default_nh.connection_details.process.integrity_level == "blah"

        default_nh.update_process(image=None)
        assert (
            default_nh.connection_details.process.image
            == "C:\\Windows\\System32\\cmd.exe"
        )

    @staticmethod
    def test_network_http_set_network_connection():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            NetworkHTTP,
            NetworkConnection,
        )

        default_nh = NetworkHTTP(request_uri="blah")
        default_nc = NetworkConnection(destination_ip="1.1.1.1")
        default_nh.set_network_connection(default_nc)
        assert default_nh.connection_details.destination_ip == "1.1.1.1"

    @staticmethod
    def test_network_http_update_connection_details():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP

        default_nh = NetworkHTTP()
        default_nh.update_connection_details(destination_ip="blah", invalid="blah")
        assert default_nh.connection_details.destination_ip == "blah"

    @staticmethod
    def test_get_process_image():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP

        default_nh = NetworkHTTP()
        assert default_nh.get_process_image() is None
        default_nh.update_process(image="blah")
        assert default_nh.get_process_image() == "blah"

    @staticmethod
    def test_get_process_pid():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP

        default_nh = NetworkHTTP()
        assert default_nh.get_process_pid() is None
        default_nh.update_process(pid=123)
        assert default_nh.get_process_pid() == 123

    @staticmethod
    def test_network_http_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP
        from uuid import UUID

        default_nh = NetworkHTTP()
        default_nh_as_primitives = default_nh.as_primitives()
        assert str(
            UUID(default_nh_as_primitives["connection_details"]["objectid"].pop("guid"))
        )
        assert default_nh_as_primitives == {
            "connection_details": {
                "objectid": {
                    "tag": None,
                    "treeid": None,
                    "processtree": None,
                    "time_observed": None,
                },
                "process": None,
                "source_ip": None,
                "source_port": None,
                "destination_ip": None,
                "destination_port": None,
                "transport_layer_protocol": None,
                "direction": None,
            },
            "request_uri": None,
            "request_headers": {},
            "request_body": None,
            "request_method": None,
            "response_headers": {},
            "response_status_code": None,
            "response_body": None,
        }


class TestMachineMetadata:
    @staticmethod
    def test_machine_metadata_init():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_mm = SandboxOntology.AnalysisMetadata.MachineMetadata()
        assert default_mm.ip is None
        assert default_mm.hypervisor is None
        assert default_mm.hostname is None
        assert default_mm.platform is None
        assert default_mm.version is None
        assert default_mm.architecture is None

        set_mm = SandboxOntology.AnalysisMetadata.MachineMetadata(
            ip="blah",
            hypervisor="blah",
            hostname="blah",
            platform="blah",
            version="blah",
            architecture="blah",
        )
        assert set_mm.ip == "blah"
        assert set_mm.hypervisor == "blah"
        assert set_mm.hostname == "blah"
        assert set_mm.platform == "blah"
        assert set_mm.version == "blah"
        assert set_mm.architecture == "blah"

    @staticmethod
    def test_machine_metadata_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_mm = SandboxOntology.AnalysisMetadata.MachineMetadata()
        assert default_mm.as_primitives() == {
            "ip": None,
            "hypervisor": None,
            "hostname": None,
            "platform": None,
            "version": None,
            "architecture": None,
        }

    @staticmethod
    def test_machine_metadata_load_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_mm = SandboxOntology.AnalysisMetadata.MachineMetadata()
        default_mm.load_from_json(
            {
                "ip": "blah",
                "hypervisor": "blah",
                "hostname": "blah",
                "platform": "blah",
                "version": "blah",
                "architecture": "blah",
            }
        )
        assert default_mm.ip == "blah"
        assert default_mm.hypervisor == "blah"
        assert default_mm.hostname == "blah"
        assert default_mm.platform == "blah"
        assert default_mm.version == "blah"
        assert default_mm.architecture == "blah"


class TestAnalysisMetadata:
    @staticmethod
    def test_analysis_metadata_init():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_am = SandboxOntology.AnalysisMetadata()
        assert default_am.task_id is None
        assert default_am.start_time is None
        assert default_am.end_time is None
        assert default_am.routing is None
        assert default_am.machine_metadata.ip is None
        assert default_am.machine_metadata.hypervisor is None
        assert default_am.machine_metadata.hostname is None
        assert default_am.machine_metadata.platform is None
        assert default_am.machine_metadata.version is None
        assert default_am.machine_metadata.architecture is None

        set_am = SandboxOntology.AnalysisMetadata(
            task_id=123,
            start_time=1.0,
            end_time=1.0,
            routing="blah",
        )
        assert set_am.task_id == 123
        assert set_am.start_time == 1.0
        assert set_am.end_time == 1.0
        assert set_am.routing == "blah"

    @staticmethod
    def test_analysis_metadata_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_am = SandboxOntology.AnalysisMetadata()
        assert default_am.as_primitives() == {
            "task_id": None,
            "start_time": None,
            "end_time": None,
            "routing": None,
            "machine_metadata": {
                "ip": None,
                "hypervisor": None,
                "hostname": None,
                "platform": None,
                "version": None,
                "architecture": None,
            },
        }

    @staticmethod
    def test_analysis_metadata_load_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_am = SandboxOntology.AnalysisMetadata()
        default_am.load_from_json(
            {
                "task_id": "blah",
                "start_time": "blah",
                "end_time": "blah",
                "routing": "blah",
                "machine_metadata": {
                    "ip": "blah",
                    "hypervisor": "blah",
                    "hostname": "blah",
                    "platform": "blah",
                    "version": "blah",
                    "architecture": "blah",
                },
            }
        )
        assert default_am.task_id == "blah"
        assert default_am.start_time == "blah"
        assert default_am.end_time == "blah"
        assert default_am.routing == "blah"
        assert default_am.machine_metadata.ip == "blah"
        assert default_am.machine_metadata.hypervisor == "blah"
        assert default_am.machine_metadata.hostname == "blah"
        assert default_am.machine_metadata.platform == "blah"
        assert default_am.machine_metadata.version == "blah"
        assert default_am.machine_metadata.architecture == "blah"


class TestSubject:
    @staticmethod
    def test_subject_init():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
            Process,
        )

        default_subject = SandboxOntology.Signature.Subject()
        assert default_subject.ip is None
        assert default_subject.domain is None
        assert default_subject.uri is None
        assert default_subject.process is None
        assert default_subject.file is None
        assert default_subject.registry is None

        set_subject = SandboxOntology.Signature.Subject(
            ip="blah",
            domain="blah",
            uri="blah",
            file="blah",
            registry="blah",
        )
        assert set_subject.ip == "blah"
        assert set_subject.domain == "blah"
        assert set_subject.uri == "blah"
        assert set_subject.file == "blah"
        assert set_subject.registry == "blah"

        p = Process(image="C:\\Windows\\System32\\cmd.exe")
        subject_w_p = SandboxOntology.Signature.Subject(process=p)
        assert subject_w_p.process.objectid.tag == "?sys32\\cmd.exe"

    @staticmethod
    def test_subject_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_subject = SandboxOntology.Signature.Subject()
        default_subject.update_process(
            guid="{12345678-1234-5678-1234-567812345678}",
            image="C:\\Windows\\System32\\cmd.exe",
        )
        assert (
            default_subject.process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert default_subject.process.image == "C:\\Windows\\System32\\cmd.exe"
        assert default_subject.process.objectid.tag == "?sys32\\cmd.exe"

    @staticmethod
    def test_subject_set_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
            Process,
        )

        default_subject = SandboxOntology.Signature.Subject()
        p1 = Process(pid=1)
        default_subject.set_process(p1)
        assert default_subject.process.pid == 1

    @staticmethod
    def test_subject_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_subject = SandboxOntology.Signature.Subject()
        assert default_subject.as_primitives() == {
            "ip": None,
            "domain": None,
            "uri": None,
            "process": None,
            "file": None,
            "registry": None,
        }


class TestSignature:
    @staticmethod
    def test_signature_init():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
            Process,
        )

        default_sig = SandboxOntology.Signature()
        assert default_sig.process is None
        assert default_sig.name is None
        assert default_sig.description is None
        assert default_sig.attack == []
        assert default_sig.subjects == []

        set_sig = SandboxOntology.Signature(
            name="blah",
            description="blah",
        )
        assert set_sig.name == "blah"
        assert set_sig.description == "blah"

        p = Process(image="C:\\Windows\\System32\\cmd.exe")
        sig_w_p = SandboxOntology.Signature.Subject(process=p)
        assert sig_w_p.process.image == "C:\\Windows\\System32\\cmd.exe"

    @staticmethod
    def test_signature_update():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_sig = SandboxOntology.Signature()
        default_sig.update(description="blah")
        assert default_sig.description == "blah"

    @staticmethod
    def test_signature_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_sig = SandboxOntology.Signature()
        default_sig.update_process(
            guid="{12345678-1234-5678-1234-567812345678}",
            image="C:\\Windows\\System32\\cmd.exe",
        )
        assert (
            default_sig.process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert default_sig.process.image == "C:\\Windows\\System32\\cmd.exe"
        assert default_sig.process.objectid.tag == "?sys32\\cmd.exe"

        default_sig.update_process(image=None)
        assert default_sig.process.image == "C:\\Windows\\System32\\cmd.exe"

    @staticmethod
    def test_signature_set_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
            Process,
        )

        default_sig = SandboxOntology.Signature()
        p1 = Process(pid=1)
        default_sig.set_process(p1)
        assert default_sig.process.pid == 1

    @staticmethod
    def test_add_attack_id():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_sig = SandboxOntology.Signature()
        default_sig.add_attack_id("T1187")
        assert default_sig.attack == [
            {
                "attack_id": "T1187",
                "categories": ["credential-access"],
                "pattern": "Forced Authentication",
            }
        ]
        # Note that it does not add duplicates
        default_sig.add_attack_id("T1187")
        assert default_sig.attack == [
            {
                "attack_id": "T1187",
                "categories": ["credential-access"],
                "pattern": "Forced Authentication",
            }
        ]

    @staticmethod
    def test_add_subject():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_sig = SandboxOntology.Signature()
        default_sig.add_subject(domain="blah")
        assert default_sig.subjects[0].domain == "blah"
        default_sig.add_subject(domain="blah")
        assert len(default_sig.subjects) == 1

    @staticmethod
    def test_add_process_subject():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_sig = SandboxOntology.Signature()
        default_sig.add_process_subject()
        assert default_sig.subjects == []
        default_sig.add_process_subject(guid="{12345678-1234-5678-1234-567812345678}")
        assert (
            default_sig.subjects[0].process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )

    @staticmethod
    def test_get_subjects():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_sig = SandboxOntology.Signature()
        default_sig.add_subject(domain="blah")
        assert default_sig.get_subjects()[0].domain == "blah"

    @staticmethod
    def test_signature_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_sig = SandboxOntology.Signature()
        assert default_sig.as_primitives() == {
            "name": None,
            "description": None,
            "attack": [],
            "subjects": [],
            "process": None,
        }


class TestSandboxOntology:
    @staticmethod
    def test_sandbox_ontology_init():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        assert default_so.analysis_metadata.task_id is None
        assert default_so.analysis_metadata.start_time is None
        assert default_so.analysis_metadata.end_time is None
        assert default_so.analysis_metadata.routing is None
        assert default_so.analysis_metadata.machine_metadata.ip is None
        assert default_so.analysis_metadata.machine_metadata.hypervisor is None
        assert default_so.analysis_metadata.machine_metadata.hostname is None
        assert default_so.analysis_metadata.machine_metadata.platform is None
        assert default_so.analysis_metadata.machine_metadata.version is None
        assert default_so.analysis_metadata.machine_metadata.architecture is None
        assert default_so.signatures == []
        assert default_so.network_connections == []
        assert default_so.network_http == []
        assert default_so.processes == []
        assert default_so.sandbox_name is None
        assert default_so.sandbox_version is None
        assert default_so._guid_process_map == {}

        set_so = SandboxOntology(sandbox_name="blah", sandbox_version="blah")
        assert set_so.sandbox_name == "blah"
        assert set_so.sandbox_version == "blah"

    @staticmethod
    def test_update_analysis_metadata():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        default_so.update_analysis_metadata(task_id=123, invalid="blah")
        assert default_so.analysis_metadata.task_id == 123

    @staticmethod
    def test_update_machine_metadata():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        default_so.update_machine_metadata(ip="blah", invalid="blah")
        assert default_so.analysis_metadata.machine_metadata.ip == "blah"

    @staticmethod
    def test_sandbox_ontology_create_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        p = default_so.create_process(
            guid="{12345678-1234-5678-1234-567812345678}",
            image="C:\\Windows\\System32\\cmd.exe",
        )
        assert p.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert p.image == "C:\\Windows\\System32\\cmd.exe"
        assert p.objectid.tag == "?sys32\\cmd.exe"

    @staticmethod
    def test_add_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        default_so = SandboxOntology()
        assert default_so.processes == []

        p = default_so.create_process(guid="{12345678-1234-5678-1234-567812345678}")
        default_so.add_process(p)
        process_as_primitives = default_so.processes[0].as_primitives()
        assert str(UUID(process_as_primitives["pobjectid"].pop("guid")))
        assert process_as_primitives == {
            "objectid": {
                "guid": "{12345678-1234-5678-1234-567812345678}",
                "tag": None,
                "treeid": None,
                "processtree": None,
                "time_observed": float("-inf"),
            },
            "pobjectid": {
                # "guid": None,
                "treeid": None,
                "processtree": None,
                "tag": None,
                "time_observed": None,
            },
            "pimage": None,
            "pcommand_line": None,
            "ppid": None,
            "pid": None,
            "image": None,
            "command_line": None,
            "start_time": float("-inf"),
            "end_time": float("inf"),
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
        }

    @staticmethod
    def test_sandbox_ontology_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        p = default_so.create_process(guid="{12345678-1234-5678-1234-567812345678}")
        default_so.add_process(p)
        assert default_so.processes[0].pid is None

        default_so.update_process(guid="{12345678-1234-5678-1234-567812345678}", pid=1)
        assert default_so.processes[0].pid == 1

        default_so.update_process(pid=1, start_time=1.0)
        assert default_so.processes[0].start_time == 1.0

        default_so.update_process(pid=1, end_time=2.0)
        assert default_so.processes[0].end_time == 2.0

        default_so.update_process(pid=None)
        assert default_so.processes[0].pid == 1

        default_so.update_process(
            image="C:\\Windows\\System32\\cmd.exe",
            pguid="{12345678-1234-5678-1234-567812345679}",
            pimage="C:\\Windows\\System32\\cmd.exe",
            pid=1,
            start_time=1.0,
        )
        assert default_so.processes[0].image == "C:\\Windows\\System32\\cmd.exe"
        assert default_so.processes[0].objectid.tag == "?sys32\\cmd.exe"
        assert default_so.processes[0].pimage == "C:\\Windows\\System32\\cmd.exe"
        assert default_so.processes[0].pobjectid.tag == '?sys32\\cmd.exe'

        parent = default_so.create_process(
            guid="{12345678-1234-5678-1234-567812345679}", image="C:\\Windows\\System32\\cmd.exe")
        default_so.add_process(parent)

        default_so.update_process(guid="{12345678-1234-5678-1234-567812345678}",
                                  pguid="{12345678-1234-5678-1234-567812345679}")
        assert default_so.processes[0].pobjectid.guid == "{12345678-1234-5678-1234-567812345679}"
        assert default_so.processes[0].pimage == "C:\\Windows\\System32\\cmd.exe"
        assert default_so.processes[0].pobjectid.tag == "?sys32\\cmd.exe"

        default_so.update_process(guid="{12345678-1234-5678-1234-567812345678}",
                                  pobjectid={"guid": "{12345678-1234-5678-1234-567812345679}"})
        assert default_so.processes[0].pobjectid.guid == "{12345678-1234-5678-1234-567812345679}"

    @staticmethod
    def test_sandboxontology_update_objectid():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        so = SandboxOntology()

        p = so.create_process(guid="{12345678-1234-5678-1234-567812345678}")
        so.add_process(p)
        nc = so.create_network_connection()
        nc_guid = nc.objectid.guid
        so.add_network_connection(nc)

        so.update_objectid()
        so.update_objectid(thing=None)
        so.update_objectid(thing="blah")
        so.update_objectid(guid="blah")

        assert p.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert p.objectid.tag is None
        assert p.objectid.treeid is None
        assert p.objectid.processtree is None
        assert p.objectid.time_observed == float("-inf")

        assert nc.objectid.guid == nc_guid
        assert nc.objectid.tag is None
        assert nc.objectid.treeid is None
        assert nc.objectid.processtree is None
        assert nc.objectid.time_observed is None

        so.update_objectid(guid="{12345678-1234-5678-1234-567812345678}", tag="blah")

        assert p.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert p.objectid.tag == "blah"
        assert p.objectid.treeid is None
        assert p.objectid.processtree is None
        assert p.objectid.time_observed == float("-inf")

        so.update_objectid(guid=nc_guid, tag="blah")

        assert nc.objectid.guid == nc_guid
        assert nc.objectid.tag == "blah"
        assert nc.objectid.treeid is None
        assert nc.objectid.processtree is None
        assert nc.objectid.time_observed is None

    @staticmethod
    def test_set_parent_details():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
            Process,
        )

        so = SandboxOntology()
        parent_process = Process(
            guid="{12345678-1234-5678-1234-567812345678}",
            image="blah.exe",
            start_time=2.0,
            end_time=3.0,
            pid=1,
            tag="blah",
        )
        so.add_process(parent_process)
        p1 = Process(pguid="{12345678-1234-5678-1234-567812345678}")
        so.set_parent_details(p1)
        assert p1.as_primitives() == {
            "objectid": {
                "guid": None,
                "tag": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
            },
            "pobjectid": {
                "guid": "{12345678-1234-5678-1234-567812345678}",
                "tag": "blah.exe",
                "treeid": None,
                "processtree": None,
                "time_observed": 2.0,
            },
            "pimage": "blah.exe",
            "pcommand_line": None,
            "ppid": 1,
            "pid": None,
            "image": None,
            "command_line": None,
            "start_time": None,
            "end_time": None,
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
        }

        p2 = Process(ppid=1, start_time=3.0)
        so.set_parent_details(p2)
        assert p2.as_primitives() == {
            "objectid": {
                "guid": None,
                "tag": None,
                "treeid": None,
                "processtree": None,
                "time_observed": 3.0,
            },
            "pobjectid": {
                "guid": "{12345678-1234-5678-1234-567812345678}",
                "tag": "blah.exe",
                "treeid": None,
                "processtree": None,
                "time_observed": 2.0,
            },
            "pimage": "blah.exe",
            "pcommand_line": None,
            "ppid": 1,
            "pid": None,
            "image": None,
            "command_line": None,
            "start_time": 3.0,
            "end_time": None,
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
        }

    @staticmethod
    def test_set_child_details():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
            Process,
        )

        so = SandboxOntology()
        child_process1 = Process(
            guid="{12345678-1234-5678-1234-567812345678}",
            image="blah.exe",
            start_time=2.0,
            end_time=3.0,
            pid=1,
            pguid="{12345678-1234-5678-1234-567812345679}",
        )
        so.add_process(child_process1)
        child_process2 = Process(
            guid="{12345678-1234-5678-1234-567812345670}",
            image="blah.exe",
            start_time=2.0,
            end_time=3.0,
            pid=3,
            ppid=2,
        )
        so.add_process(child_process2)
        parent = Process(
            guid="{12345678-1234-5678-1234-567812345679}",
            pid=2,
            start_time=2.0,
            image="parent.exe",
            tag="blah",
        )
        so.set_child_details(parent)
        assert child_process1.as_primitives() == {
            "objectid": {
                "guid": "{12345678-1234-5678-1234-567812345678}",
                "tag": "blah.exe",
                "treeid": None,
                "processtree": None,
                "time_observed": 2.0,
            },
            "pobjectid": {
                "guid": "{12345678-1234-5678-1234-567812345679}",
                "tag": "parent.exe",
                "treeid": None,
                "processtree": None,
                "time_observed": 2.0,
            },
            "pimage": "parent.exe",
            "pcommand_line": None,
            "ppid": 2,
            "pid": 1,
            "image": "blah.exe",
            "command_line": None,
            "start_time": 2.0,
            "end_time": 3.0,
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
        }
        assert child_process2.as_primitives() == {
            "objectid": {
                "guid": "{12345678-1234-5678-1234-567812345670}",
                "tag": "blah.exe",
                "treeid": None,
                "processtree": None,
                "time_observed": 2.0,
            },
            "pobjectid": {
                "guid": "{12345678-1234-5678-1234-567812345679}",
                "tag": "parent.exe",
                "treeid": None,
                "processtree": None,
                "time_observed": 2.0,
            },
            "pimage": "parent.exe",
            "pcommand_line": None,
            "ppid": 2,
            "pid": 3,
            "image": "blah.exe",
            "command_line": None,
            "start_time": 2.0,
            "end_time": 3.0,
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
        }

    @staticmethod
    @pytest.mark.parametrize(
        "events, validated_events_num",
        [
            (
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "timestamp": 1.0,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "pguid": "{12345678-1234-5678-1234-567812345679}",
                    }
                ],
                1,
            ),
        ],
    )
    def test_get_processes(events, validated_events_num):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        for event in events:
            p = so.create_process(**event)
            so.add_process(p)
        assert len(so.get_processes()) == validated_events_num

    @staticmethod
    def test_get_guid_by_pid_and_time():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        assert so.get_guid_by_pid_and_time(1, 0.0) is None

        p = so.create_process(
            pid=1,
            start_time=0.0,
            end_time=1.0,
            guid="{12345678-1234-5678-1234-567812345678}",
        )
        so.add_process(p)
        assert (
            so.get_guid_by_pid_and_time(1, 0.5)
            == "{12345678-1234-5678-1234-567812345678}"
        )

    @staticmethod
    def test_get_processes_by_ppid_and_time():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        assert so.get_processes_by_ppid_and_time(1, 0.0) == []

        p = so.create_process(
            pid=1,
            start_time=0.0,
            end_time=1.0,
            guid="{12345678-1234-5678-1234-567812345678}",
            ppid=2,
        )
        so.add_process(p)
        assert so.get_processes_by_ppid_and_time(2, 0.5) == [p]

    @staticmethod
    def test_get_pguid_by_pid_and_time():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        assert so.get_pguid_by_pid_and_time(1, 0.0) is None

        child = so.create_process(
            pid=1,
            start_time=0.0,
            end_time=1.0,
            pguid="{12345678-1234-5678-1234-567812345678}",
        )
        so.add_process(child)
        assert (
            so.get_pguid_by_pid_and_time(1, 0.5)
            == "{12345678-1234-5678-1234-567812345678}"
        )

    @staticmethod
    def test_is_guid_in_gpm():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        guid = "{12345678-1234-5678-1234-567812345678}"
        assert not so.is_guid_in_gpm(guid)

        p = so.create_process(pid=1, start_time=0.0, end_time=1.0, guid=guid)
        so.add_process(p)
        assert so.is_guid_in_gpm(guid)

    @staticmethod
    def test_get_process_by_guid():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        assert not so.get_process_by_guid(None)

        guid = "{12345678-1234-5678-1234-567812345678}"
        assert not so.get_process_by_guid(guid)

        p = so.create_process(guid=guid)
        so.add_process(p)
        assert so.get_process_by_guid(guid) == p

    @staticmethod
    def test_get_process_by_command_line():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        assert so.get_process_by_command_line() is None

        p1 = so.create_process(command_line="blah1")
        p2 = so.create_process(command_line="blah2")
        p3 = so.create_process(command_line="blah1")
        so.add_process(p1)
        so.add_process(p2)
        so.add_process(p3)

        assert so.get_process_by_command_line() is None
        assert so.get_process_by_command_line("blah2") == p2
        assert so.get_process_by_command_line("blah1") == p1

    @staticmethod
    def test_get_process_by_pid_and_time():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        assert so.get_process_by_pid_and_time(None, 1.0) is None
        assert so.get_process_by_pid_and_time(1, None) is None
        assert so.get_process_by_pid_and_time(1, 1.0) is None

        p = so.create_process(pid=1, start_time=1.0, end_time=2.0)
        so.add_process(p)
        assert so.get_process_by_pid_and_time(1, 1.5) == p

    @staticmethod
    def test_get_processes_by_pguid():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        assert not so.get_processes_by_pguid(None)

        guid = "{12345678-1234-5678-1234-567812345678}"
        assert not so.get_processes_by_pguid(guid)

        p = so.create_process(pguid=guid)
        so.add_process(p)
        assert so.get_processes_by_pguid(guid) == [p]

    @staticmethod
    def test_create_network_connection():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nc = default_so.create_network_connection(
            destination_ip="1.1.1.1"
        )
        assert nc.destination_ip == "1.1.1.1"

    @staticmethod
    def test_add_network_connection():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        default_so = SandboxOntology()
        assert default_so.network_connections == []

        nc1 = default_so.create_network_connection()
        default_so.add_network_connection(nc1)
        nc1_as_primitives = default_so.network_connections[0].as_primitives()
        assert str(UUID(nc1_as_primitives["objectid"].pop("guid")))
        assert nc1_as_primitives == {
            "objectid": {
                "tag": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
            },
            "process": None,
            "source_ip": None,
            "source_port": None,
            "destination_ip": None,
            "destination_port": None,
            "transport_layer_protocol": None,
            "direction": None,
        }

        nc2 = default_so.create_network_connection(
            source_ip="2.2.2.2",
            source_port=321,
            destination_ip="1.1.1.1",
            destination_port=123,
            direction="outbound",
            time_observed=1,
        )
        default_so.add_network_connection(nc2)
        assert nc2.objectid.tag == "1.1.1.1:123"

    @staticmethod
    def test_get_network_connections():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nc = default_so.create_network_connection()
        default_so.add_network_connection(nc)
        assert default_so.get_network_connections() == [nc]

    @staticmethod
    def test_get_network_connection_by_pid():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nc = default_so.create_network_connection(destination_ip="1.1.1.1")
        nc.update_process(pid=1)
        default_so.add_network_connection(nc)
        assert default_so.get_network_connection_by_pid(1) == []

        p = default_so.create_process(pid=2, start_time=1.0, end_time=5.0)
        default_so.add_process(p)
        nc2 = default_so.create_network_connection(
            destination_ip="1.1.1.1", timestamp=2.0
        )
        nc2.update_process(pid=2, start_time=2.0)
        default_so.add_network_connection(nc2)
        assert (
            default_so.get_network_connection_by_pid(2)[0].destination_ip == "1.1.1.1"
        )

    @staticmethod
    def test_get_network_connection_by_details():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nc = default_so.create_network_connection(
            destination_ip="1.1.1.1",
            destination_port=1,
            source_ip="2.2.2.2",
            source_port=2,
            direction="outbound",
            transport_layer_protocol="tcp",
        )
        default_so.add_network_connection(nc)
        assert (
            default_so.get_network_connection_by_details(
                source_ip="2.2.2.2",
                source_port=2,
                destination_ip="1.1.1.1",
                destination_port=1,
                direction="outbound",
                transport_layer_protocol="tcp",
            )
            == nc
        )
        assert (
            default_so.get_network_connection_by_details(
                source_ip=None,
                source_port=2,
                destination_ip="1.1.1.1",
                destination_port=1,
                direction="outbound",
                transport_layer_protocol="tcp",
            )
            is None
        )

    @staticmethod
    def test_create_network_dns():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nd = default_so.create_network_dns(domain="blah")
        assert nd.domain == "blah"

    @staticmethod
    def test_add_network_dns():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        default_so = SandboxOntology()
        assert default_so.network_dns == []

        nd = default_so.create_network_dns()
        default_so.add_network_dns(nd)
        nd_as_primitives = default_so.network_dns[0].as_primitives()
        assert str(UUID(nd_as_primitives["connection_details"]["objectid"].pop("guid")))
        assert nd_as_primitives == {
            "connection_details": {
                "objectid": {
                    "tag": None,
                    "treeid": None,
                    "processtree": None,
                    "time_observed": None,
                },
                "process": None,
                "source_ip": None,
                "source_port": None,
                "destination_ip": None,
                "destination_port": 53,
                "transport_layer_protocol": "udp",
                "direction": "outbound",
            },
            "domain": None,
            "resolved_ips": [],
            "lookup_type": None,
        }
        assert default_so.get_network_connections()[0] == nd.connection_details

        dns1 = default_so.create_network_dns(
            domain="blah.com", resolved_ips=["1.1.1.1"]
        )
        dns1.update_connection_details(destination_port=123, direction="outbound")
        default_so.add_network_dns(dns1)
        assert dns1.connection_details.objectid.tag == "blah.com:123"

    @staticmethod
    def test_get_network_dns():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nd = default_so.create_network_dns()
        default_so.add_network_dns(nd)
        assert default_so.get_network_dns() == [nd]

    @staticmethod
    def test_get_domain_by_destination_ip():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        assert default_so.get_domain_by_destination_ip("1.1.1.1") is None

        nd1 = default_so.create_network_dns(domain="blah.com", resolved_ips=["1.1.1.1"])
        default_so.add_network_dns(nd1)
        assert default_so.get_domain_by_destination_ip("1.1.1.1") == "blah.com"

        nd2 = default_so.create_network_dns(domain="blah.ca", resolved_ips=["1.1.1.1"])
        default_so.add_network_dns(nd2)
        assert default_so.get_domain_by_destination_ip("1.1.1.1") == "blah.com"

    @staticmethod
    def test_get_destination_ip_by_domain():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        assert default_so.get_destination_ip_by_domain("blah.com") is None

        nd1 = default_so.create_network_dns(domain="blah.com", resolved_ips=["1.1.1.1"])
        default_so.add_network_dns(nd1)
        assert default_so.get_destination_ip_by_domain("blah.com") == "1.1.1.1"

        nd2 = default_so.create_network_dns(domain="blah.com", resolved_ips=["2.2.2.2"])
        default_so.add_network_dns(nd2)
        assert default_so.get_destination_ip_by_domain("blah.com") == "1.1.1.1"

    @staticmethod
    def test_create_network_http():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nh = default_so.create_network_http(request_uri="blah")
        assert nh.request_uri == "blah"

    @staticmethod
    def test_add_network_http():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        default_so = SandboxOntology()
        assert default_so.network_http == []

        nh = default_so.create_network_http()
        default_so.add_network_http(nh)
        nh_as_primitives = default_so.network_http[0].as_primitives()
        assert str(UUID(nh_as_primitives["connection_details"]["objectid"].pop("guid")))
        assert nh_as_primitives == {
            "connection_details": {
                "objectid": {
                    "tag": None,
                    "treeid": None,
                    "processtree": None,
                    "time_observed": None,
                },
                "process": None,
                "source_ip": None,
                "source_port": None,
                "destination_ip": None,
                "destination_port": 80,
                "transport_layer_protocol": "tcp",
                "direction": "outbound",
            },
            "request_uri": None,
            "request_headers": {},
            "request_body": None,
            "request_method": None,
            "response_headers": {},
            "response_status_code": None,
            "response_body": None,
        }
        assert default_so.get_network_connections()[0] == nh.connection_details

    @staticmethod
    def test_get_network_http():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nh = default_so.create_network_http()
        default_so.add_network_http(nh)
        assert default_so.get_network_http() == [nh]

    @staticmethod
    def test_get_network_http_by_path():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nh = default_so.create_network_http(
            request_body_path="/blah1", response_body_path="/blah2"
        )
        default_so.add_network_http(nh)

        assert default_so.get_network_http_by_path("/blah1") == nh
        assert default_so.get_network_http_by_path("/blah2") == nh

    @staticmethod
    def test_get_network_http_by_details():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nh = default_so.create_network_http(
            request_uri="http://blah.com", request_method="GET", request_headers={"a": "b"}
        )
        default_so.add_network_http(nh)

        assert default_so.get_network_http_by_details("http://blah.com", "GET", {"a": "b"}) == nh
        assert default_so.get_network_http_by_details("http://blah.ca", "GET", {"a": "b"}) is None

    @staticmethod
    def test_create_signature():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        s = default_so.create_signature(name="blah", invalid="blah")
        assert s.name == "blah"

    @staticmethod
    def test_add_signature():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        default_so = SandboxOntology()
        assert default_so.network_http == []

        s = default_so.create_signature()
        default_so.add_signature(s)
        assert default_so.get_signatures() == []

        s.update_process(guid="{12345678-1234-5678-1234-567812345678}")
        default_so.add_signature(s)
        assert default_so.get_signatures() == []

        p = default_so.create_process(guid="{12345678-1234-5678-1234-567812345678}")
        default_so.add_process(p)
        s.update_process(guid="{12345678-1234-5678-1234-567812345678}")
        default_so.add_signature(s)
        sig_as_prims = default_so.signatures[0].as_primitives()
        assert str(UUID(sig_as_prims["process"]["pobjectid"].pop("guid")))
        assert sig_as_prims == {
            'process':
            {'start_time': float("-inf"), 'end_time': float("inf"),
             'objectid':
             {'guid': '{12345678-1234-5678-1234-567812345678}', 'tag': None, 'treeid': None, 'processtree': None,
              'time_observed': float("-inf")},
             'pobjectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None},
             'pimage': None, 'pcommand_line': None, 'ppid': None, 'pid': None, 'image': None, 'command_line': None,
             'integrity_level': None, 'image_hash': None, 'original_file_name': None},
            'name': None, 'description': None, 'attack': [],
            'subjects': []}

        s2 = default_so.create_signature()
        s2.add_process_subject(**p.as_primitives())
        s2.add_process_subject(**p.as_primitives())
        s2.add_process_subject(**p.as_primitives())
        s2.add_process_subject(**p.as_primitives())
        default_so.add_signature(s2)
        sig2_as_prims = default_so.signatures[1].as_primitives()
        assert len(sig2_as_prims["subjects"]) == 1
        assert str(UUID(sig2_as_prims["subjects"][0]["process"]["pobjectid"].pop("guid")))
        assert sig2_as_prims == {
            'process': None, 'name': None, 'description': None, 'attack': [],
            'subjects':
            [{'ip': None, 'domain': None, 'uri': None, 'file': None, 'registry': None,
              'process':
              {'start_time': float("-inf"),
               'end_time': float("inf"),
               'objectid':
               {'guid': '{12345678-1234-5678-1234-567812345678}', 'tag': None, 'treeid': None, 'processtree': None,
                'time_observed': float("-inf")},
               'pobjectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None},
               'pimage': None, 'pcommand_line': None, 'ppid': None, 'pid': None, 'image': None, 'command_line': None,
               'integrity_level': None, 'image_hash': None, 'original_file_name': None}}]}

        s3 = default_so.create_signature(name="blah")
        s3.add_process_subject(start_time=1.0)
        default_so.add_signature(s3)
        assert s3.subjects == []

    @staticmethod
    def test_get_signatures():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        sig = default_so.create_signature(name="blah")
        default_so.add_signature(sig)
        assert default_so.get_signatures()[0].name == "blah"

    @staticmethod
    def test_get_signatures_by_pid():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        p = default_so.create_process(pid=1, start_time=5, end_time=6)
        default_so.add_process(p)
        sig = default_so.create_signature(name="blah")
        sig.update_process(pid=1, start_time=5.5)
        default_so.add_signature(sig)
        assert default_so.get_signatures_by_pid(1)[0].name == "blah"

    @staticmethod
    def test_set_sandbox_name():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        default_so.set_sandbox_name("blah")
        assert default_so.sandbox_name == "blah"

    @staticmethod
    def test_set_sandbox_version():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        default_so.set_sandbox_version("blah")
        assert default_so.sandbox_version == "blah"

    @staticmethod
    def test_sandbox_ontology_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        assert default_so.as_primitives() == {
            "analysis_metadata": {
                "task_id": None,
                "start_time": None,
                "end_time": None,
                "routing": None,
                "machine_metadata": {
                    "ip": None,
                    "hypervisor": None,
                    "hostname": None,
                    "platform": None,
                    "version": None,
                    "architecture": None,
                },
            },
            "signatures": [],
            "network_connections": [],
            "network_dns": [],
            "network_http": [],
            "processes": [],
            "sandbox_name": None,
            "sandbox_version": None,
        }

    @staticmethod
    def test_get_events():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        p = so.create_process(
            pid=1,
            ppid=1,
            image="blah",
            command_line="blah",
            time_observed=1.0,
            guid="{12345678-1234-5678-1234-567812345678}",
            pguid="{12345678-1234-5678-1234-567812345679}",
            treeid="blahblah"
        )
        so.add_process(p)
        nc = so.create_network_connection(
            transport_layer_protocol="blah",
            source_ip="blah",
            source_port=1,
            destination_ip="blah",
            destination_port=1,
            time_observed=1.0,
            guid="{12345678-1234-5678-1234-567812345670}",
        )
        so.add_network_connection(nc)
        assert so.get_events() == [p, nc]
        assert so.get_events(["blahblah"]) == [nc]

    @staticmethod
    def test_get_non_safelisted_processes():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        safelist = ["blahblah"]
        p1 = so.create_process(treeid="blahblah")
        p2 = so.create_process(treeid="blahblahblah")
        so.add_process(p1)
        so.add_process(p2)
        assert so.get_non_safelisted_processes(safelist) == [p2]

    @staticmethod
    @pytest.mark.parametrize(
        "event_list, safelist, expected_result",
        [
            (None, [], []),
            ([], [], []),
            # One process, tags for both objectid and pobjectid
            (
                [
                    {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    }
                ],
                ["blah"],
                [
                    {
                        "pid": 2,
                        "image": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52",
                            "processtree": "blah|blah",
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "ppid": 1,
                        "integrity_level": None,
                        "image_hash": None,
                        "original_file_name": None,
                        "command_line": "blah",
                        "pimage": None,
                        "pcommand_line": None,
                        "children": [],
                    }
                ],
            ),
            # Two processes, one parent one child
            (
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah2",
                        "command_line": "blah2",
                        "start_time": 2,
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": "blah2",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                ],
                [],
                [
                    {
                        "pid": 1,
                        "image": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52",
                            "processtree": "blah|blah",
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "ppid": 1,
                        "command_line": "blah",
                        "pimage": None,
                        "pcommand_line": None,
                        "integrity_level": None,
                        "image_hash": None,
                        "original_file_name": None,
                        "children": [
                            {
                                "pid": 2,
                                "image": "blah2",
                                "start_time": 2,
                                "end_time": float("inf"),
                                "objectid": {
                                    "guid": "{12345678-1234-5678-1234-567812345679}",
                                    "tag": "blah2",
                                    "treeid": "28fb5ed121e549f67b678d225bb2fc9971ed02c18a087f8fa9b05bf18a23d9e1",
                                    "processtree": "blah|blah|blah2",
                                    "time_observed": 2,
                                },
                                "pobjectid": {
                                    "guid": "{12345678-1234-5678-1234-567812345678}",
                                    "tag": "blah",
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 1,
                                },
                                "ppid": 1,
                                "command_line": "blah2",
                                "pimage": "blah",
                                "pcommand_line": "blah",
                                "children": [],
                                "integrity_level": None,
                                "image_hash": None,
                                "original_file_name": None,
                            }
                        ],
                    }
                ],
            ),
            # Four processes, two pairs of parent-child, one child is safelisted
            (
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345671}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345671}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah2",
                        "command_line": "blah2",
                        "start_time": 2,
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345672}",
                            "tag": "blah2",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345671}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                    },
                    {
                        "pid": 3,
                        "ppid": 3,
                        "image": "blah3",
                        "command_line": "blah3",
                        "start_time": 1,
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345673}",
                            "tag": "blah3",
                            "treeid": None,
                                        "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345673}",
                            "tag": "blah3",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                    },
                    {
                        "pid": 4,
                        "ppid": 3,
                        "image": "blah4",
                        "command_line": "blah4",
                        "start_time": 2,
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345674}",
                            "tag": "blah4",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345673}",
                            "tag": "blah3",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                    },
                ],
                ["55459caaa8ca94a90de5643a6a930e1b19bab480982607327081f46eb86f816c"],
                [
                    {
                        "pid": 1,
                        "image": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345671}",
                            "tag": "blah",
                            "treeid": "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52",
                            "processtree": "blah|blah",
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345671}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "ppid": 1,
                        "command_line": "blah",
                        "pimage": None,
                        "pcommand_line": None,
                        "integrity_level": None,
                        "image_hash": None,
                        "original_file_name": None,
                        "children": [
                            {
                                "pid": 2,
                                "image": "blah2",
                                "start_time": 2,
                                "end_time": float("inf"),
                                "objectid": {
                                    "guid": "{12345678-1234-5678-1234-567812345672}",
                                    "tag": "blah2",
                                    "treeid": "28fb5ed121e549f67b678d225bb2fc9971ed02c18a087f8fa9b05bf18a23d9e1",
                                    "processtree": "blah|blah|blah2",
                                    "time_observed": 2,
                                },
                                "pobjectid": {
                                    "guid": "{12345678-1234-5678-1234-567812345671}",
                                    "tag": "blah",
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 1,
                                },
                                "ppid": 1,
                                "command_line": "blah2",
                                "children": [],
                                "pimage": "blah",
                                "pcommand_line": "blah",
                                "integrity_level": None,
                                "image_hash": None,
                                "original_file_name": None,
                            }
                        ],
                    },
                ],
            ),
            # One process, safelisted
            (
                [
                    {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    }
                ],
                ["8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52"],
                [],
            ),
            # One network connection
            (
                [
                    {
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": "blah",
                        },
                        "source_ip": "blah",
                        "source_port": "blah",
                        "destination_ip": "blah",
                        "destination_port": "blah",
                        "transport_layer_protocol": "blah",
                        "direction": "blah",
                        "process": None,
                    },
                ],
                ["blah"],
                [
                    {
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah:blah",
                            "treeid": "5f687d6145fb95eb502e4b6c1c83914aca058b35ce0aa6fe3d80f7e972e4f363",
                            "processtree": "blah:blah",
                            "time_observed": "blah",
                        },
                        "source_ip": "blah",
                        "source_port": "blah",
                        "destination_ip": "blah",
                        "destination_port": "blah",
                        "transport_layer_protocol": "blah",
                        "direction": "blah",
                        "process": None,
                        "children": [],
                    },
                ],
            ),
            # Two objects, one parent process, one child network connection
            (
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    {
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": "blah:blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                        "source_ip": "blah",
                        "source_port": "blah",
                        "destination_ip": "blah",
                        "destination_port": "blah",
                        "transport_layer_protocol": "blah",
                        "direction": "blah",
                        "process": {
                            "objectid": {
                                "guid": "{12345678-1234-5678-1234-567812345678}"
                            }
                        },
                    },
                ],
                [],
                [
                    {
                        "pid": 1,
                        "image": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52",
                            "processtree": "blah|blah",
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "ppid": 1,
                        "command_line": "blah",
                        "pimage": None,
                        "pcommand_line": None,
                        "integrity_level": None,
                        "image_hash": None,
                        "original_file_name": None,
                        "children": [
                            {
                                "objectid": {
                                    "guid": "{12345678-1234-5678-1234-567812345679}",
                                    "tag": "blah:blah",
                                    "treeid": "81a167be9a70e6d9c9b14f4dec79c052e463c3fda116583731c1065143e8f277",
                                    "processtree": "blah|blah|blah:blah",
                                    "time_observed": 2,
                                },
                                "source_ip": "blah",
                                "source_port": "blah",
                                "destination_ip": "blah",
                                "destination_port": "blah",
                                "transport_layer_protocol": "blah",
                                "direction": "blah",
                                "process": {
                                    "pid": 1,
                                    "ppid": 1,
                                    "image": "blah",
                                    "command_line": "blah",
                                    "start_time": 1,
                                    "end_time": float("inf"),
                                    "pimage": None,
                                    "pcommand_line": None,
                                    "integrity_level": None,
                                    "image_hash": None,
                                    "original_file_name": None,
                                    "objectid": {
                                        "guid": "{12345678-1234-5678-1234-567812345678}",
                                        "tag": "blah",
                                        "treeid": None,
                                        "processtree": None,
                                        "time_observed": 1,
                                    },
                                    "pobjectid": {
                                        "guid": "{12345678-1234-5678-1234-567812345678}",
                                        "tag": "blah",
                                        "treeid": None,
                                        "processtree": None,
                                        "time_observed": None,
                                    },
                                },
                                "children": [],
                            },
                        ],
                    }
                ],
            ),
        ],
    )
    def test_get_process_tree(event_list, safelist, expected_result, mocker):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        o = SandboxOntology()
        if event_list:
            for event in event_list:
                if "process" in event:
                    mocker.patch("assemblyline_v4_service.common.dynamic_service_helper.uuid4",
                                 return_value=event["objectid"]["guid"][1: -1])
                    nc = o.create_network_connection(**event)
                    o.add_network_connection(nc)
                else:
                    p = o.create_process(**event)
                    o.add_process(p)
        actual_result = o.get_process_tree(safelist=safelist)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "event_list, signatures, safelist, correct_section_body",
        [
            (None, None, [], []),
            ([], None, [], []),
            (
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    }
                ],
                None,
                [],
                [
                    {
                        "process_pid": 1,
                        "process_name": "blah",
                        "command_line": "blah",
                        "signatures": {},
                        "children": [],
                        "file_count": 0,
                        "network_count": 0,
                        "registry_count": 0,
                        "safelisted": False,
                    }
                ],
            ),
            (
                [
                    {
                        "pid": 1,
                        "ppid": 2,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                    },
                    {
                        "pid": 2,
                        "ppid": 3,
                        "image": "blah2",
                        "command_line": "blah2",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345677}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                ],
                None,
                [],
                [
                    {
                        "process_pid": 2,
                        "process_name": "blah2",
                        "command_line": "blah2",
                        "signatures": {},
                        "children": [
                            {
                                "process_pid": 1,
                                "process_name": "blah",
                                "command_line": "blah",
                                "signatures": {},
                                "children": [],
                                "file_count": 0,
                                "network_count": 0,
                                "registry_count": 0,
                                "safelisted": False,
                            }
                        ],
                        "file_count": 0,
                        "network_count": 1,
                        "registry_count": 0,
                        "safelisted": False,
                    }
                ],
            ),
            (
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah2",
                        "command_line": "blah2",
                        "start_time": 2,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": "blah2",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                    },
                    {
                        "pid": 3,
                        "ppid": 3,
                        "image": "blah3",
                        "command_line": "blah3",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345671}",
                            "tag": "blah3",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345671}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    {
                        "pid": 4,
                        "ppid": 3,
                        "image": "blah4",
                        "command_line": "blah4",
                        "start_time": 2,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345674}",
                            "tag": "blah4",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345671}",
                            "tag": "blah3",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                    },
                ],
                None,
                ["55459caaa8ca94a90de5643a6a930e1b19bab480982607327081f46eb86f816c"],
                [
                    {
                        "process_pid": 1,
                        "process_name": "blah",
                        "command_line": "blah",
                        "signatures": {},
                        "children": [
                            {
                                "process_pid": 2,
                                "process_name": "blah2",
                                "command_line": "blah2",
                                "signatures": {},
                                "children": [],
                                "file_count": 0,
                                "network_count": 1,
                                "registry_count": 0,
                                "safelisted": False,
                            }
                        ],
                        "file_count": 0,
                        "network_count": 0,
                        "registry_count": 0,
                        "safelisted": False,
                    }
                ],
            ),
            (
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    }
                ],
                [{"process.pid": 1, "name": "blah", "score": 1, "process.start_time": 1}],
                [],
                [
                    {
                        "process_pid": 1,
                        "process_name": "blah",
                        "command_line": "blah",
                        "signatures": {"blah": 1},
                        "children": [],
                        "file_count": 0,
                        "network_count": 0,
                        "registry_count": 0,
                        "safelisted": False,
                    }
                ],
            ),
            (
                [
                    {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    }
                ],
                [{"process.pid": 1, "name": "blah", "score": 1}],
                [],
                [
                    {
                        "process_pid": 2,
                        "process_name": "blah",
                        "command_line": "blah",
                        "signatures": {},
                        "children": [],
                        "file_count": 0,
                        "network_count": 0,
                        "registry_count": 0,
                        "safelisted": False,
                    }
                ],
            ),
            (
                [
                    {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    }
                ],
                [{"process.pid": 1, "name": "blah", "score": 1}],
                ["blah"],
                [
                    {
                        "process_pid": 2,
                        "process_name": "blah",
                        "command_line": "blah",
                        "signatures": {},
                        "children": [],
                        "file_count": 0,
                        "file_count": 0,
                        "network_count": 0,
                        "registry_count": 0,
                        "safelisted": False,
                    }
                ],
            ),
            (
                [
                    {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "end_time": float("inf"),
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    }
                ],
                [{"process.pid": 1, "name": "blah", "score": 1}],
                ["8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52"],
                [],
            ),
        ],
    )
    def test_get_process_tree_result_section(
        event_list, signatures, safelist, correct_section_body
    ):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from assemblyline_v4_service.common.result import ResultProcessTreeSection

        o = SandboxOntology()
        if event_list:
            for event in event_list:
                p = o.create_process(**event)
                o.add_process(p)
        nc = o.create_network_connection(
            **{
                "destination_ip": "1.1.1.1",
                "destination_port": 443,
                "source_ip": "2.2.2.2",
                "source_port": 9999,
                "transport_layer_protocol": "tcp",
            }
        )
        nc.update_process(
            **{
                "pid": 2,
                "image": "blah2",
                "start_time": 2,
                "end_time": float("inf"),
                "guid": "{12345678-1234-5678-1234-567812345679}",
                "pguid": "{12345678-1234-5678-1234-567812345673}",
            }
        )
        o.add_network_connection(nc)
        if signatures:
            for signature in signatures:
                s = o.create_signature(
                    **{k: v for k, v in signature.items() if "." not in k}
                )
                s.update_process(
                    **{k.split(".")[1]: v for k, v in signature.items() if "." in k}
                )
                o.add_signature(s)
        actual_result = o.get_process_tree_result_section(safelist=safelist)
        assert isinstance(actual_result, ResultProcessTreeSection)
        assert actual_result.section_body.__dict__["_data"] == correct_section_body

    @staticmethod
    def test_load_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        default_so = SandboxOntology()
        default_so.load_from_json(
            {
                "analysis_metadata": {
                    "task_id": "blah",
                    "start_time": "blah",
                    "end_time": "blah",
                    "routing": "blah",
                    "machine_metadata": {
                        "ip": "blah",
                        "hypervisor": "blah",
                        "hostname": "blah",
                        "platform": "blah",
                        "version": "blah",
                        "architecture": "blah",
                    },
                },
                "signatures": [
                    {
                        "name": "blah",
                        "description": "blah",
                        "attack": ["blah"],
                        "subjects": [
                            {
                                "ip": "blah",
                                "domain": None,
                                "uri": None,
                                "process": None,
                                "file": None,
                                "registry": None,
                            },
                            {
                                "ip": "blah",
                                "domain": None,
                                "uri": None,
                                "process": {
                                    "objectid": {
                                        "guid": "{12345678-1234-5678-1234-567812345678}",
                                        "tag": "blah",
                                        "treeid": "blah",
                                        "processtree": "blah",
                                        "time_observed": "blah",
                                    },
                                    "pobjectid": {
                                        "guid": "{12345678-1234-5678-1234-567812345678}",
                                        "tag": "blah",
                                        "treeid": "blah",
                                        "processtree": "blah",
                                        "time_observed": "blah",
                                    },
                                    "pimage": "blah",
                                    "pcommand_line": "blah",
                                    "ppid": "blah",
                                    "pid": "blah",
                                    "image": "blah",
                                    "command_line": "blah",
                                    "start_time": "blah",
                                    "end_time": "blah",
                                    "integrity_level": "blah",
                                    "image_hash": "blah",
                                    "original_file_name": "blah",
                                },
                                "file": None,
                                "registry": None,
                            },
                        ],
                        "process": {
                            "objectid": {
                                "guid": "{12345678-1234-5678-1234-567812345678}",
                                "tag": "blah",
                                "treeid": "blah",
                                "processtree": "blah",
                                "time_observed": "blah",
                            },
                            "pobjectid": {
                                "guid": "{12345678-1234-5678-1234-567812345678}",
                                "tag": "blah",
                                "treeid": "blah",
                                "processtree": "blah",
                                "time_observed": "blah",
                            },
                            "pimage": "blah",
                            "pcommand_line": "blah",
                            "ppid": "blah",
                            "pid": "blah",
                            "image": "blah",
                            "command_line": "blah",
                            "start_time": "blah",
                            "end_time": "blah",
                            "integrity_level": "blah",
                            "image_hash": "blah",
                            "original_file_name": "blah",
                        },
                    }
                ],
                "network_connections": [
                    {
                        "objectid": {
                            "tag": "blah",
                            "treeid": "blah",
                            "processtree": "blah",
                            "time_observed": "blah",
                        },
                        "source_ip": "blah",
                        "source_port": "blah",
                        "destination_ip": "blah",
                        "destination_port": "blah",
                        "transport_layer_protocol": "blah",
                        "direction": "blah",
                        "process": {
                            "objectid": {
                                "guid": "{12345678-1234-5678-1234-567812345678}",
                                "tag": "blah",
                                "treeid": "blah",
                                "processtree": "blah",
                                "time_observed": "blah",
                            },
                            "pobjectid": {
                                "guid": "{12345678-1234-5678-1234-567812345678}",
                                "tag": "blah",
                                "treeid": "blah",
                                "processtree": "blah",
                                "time_observed": "blah",
                            },
                            "pimage": "blah",
                            "pcommand_line": "blah",
                            "ppid": "blah",
                            "pid": "blah",
                            "image": "blah",
                            "command_line": "blah",
                            "start_time": "blah",
                            "end_time": "blah",
                            "integrity_level": "blah",
                            "image_hash": "blah",
                            "original_file_name": "blah",
                        },
                    }
                ],
                "network_dns": [
                    {
                        "domain": "blah",
                        "resolved_ips": ["blah"],
                        "lookup_type": "blah",
                        "connection_details": {
                            "objectid": {
                                "tag": "blah",
                                "treeid": "blah",
                                "processtree": "blah",
                                "time_observed": "blah",
                            },
                            "source_ip": "blah",
                            "source_port": "blah",
                            "destination_ip": "blah",
                            "destination_port": "blah",
                            "transport_layer_protocol": "blah",
                            "direction": "blah",
                            "process": {
                                "objectid": {
                                    "guid": "{12345678-1234-5678-1234-567812345678}",
                                    "tag": "blah",
                                    "treeid": "blah",
                                    "processtree": "blah",
                                    "time_observed": "blah",
                                },
                                "pobjectid": {
                                    "guid": "{12345678-1234-5678-1234-567812345678}",
                                    "tag": "blah",
                                    "treeid": "blah",
                                    "processtree": "blah",
                                    "time_observed": "blah",
                                },
                                "pimage": "blah",
                                "pcommand_line": "blah",
                                "ppid": "blah",
                                "pid": "blah",
                                "image": "blah",
                                "command_line": "blah",
                                "start_time": "blah",
                                "end_time": "blah",
                                "integrity_level": "blah",
                                "image_hash": "blah",
                                "original_file_name": "blah",
                            },
                        },
                    }
                ],
                "network_http": [
                    {
                        "request_uri": "blah",
                        "request_headers": {"a": "b"},
                        "request_body": "blah",
                        "request_method": "blah",
                        "response_headers": {"a": "b"},
                        "response_status_code": 123,
                        "response_body": "blah",
                        "connection_details": {
                            "objectid": {
                                "tag": "blah",
                                "treeid": "blah",
                                "processtree": "blah",
                                "time_observed": "blah",
                            },
                            "source_ip": "blah",
                            "source_port": "blah",
                            "destination_ip": "blah",
                            "destination_port": "blah",
                            "transport_layer_protocol": "blah",
                            "direction": "blah",
                            "process": {
                                "objectid": {
                                    "guid": "{12345678-1234-5678-1234-567812345678}",
                                    "tag": "blah",
                                    "treeid": "blah",
                                    "processtree": "blah",
                                    "time_observed": "blah",
                                },
                                "pobjectid": {
                                    "guid": "{12345678-1234-5678-1234-567812345678}",
                                    "tag": "blah",
                                    "treeid": "blah",
                                    "processtree": "blah",
                                    "time_observed": "blah",
                                },
                                "pimage": "blah",
                                "pcommand_line": "blah",
                                "ppid": "blah",
                                "pid": "blah",
                                "image": "blah",
                                "command_line": "blah",
                                "start_time": "blah",
                                "end_time": "blah",
                                "integrity_level": "blah",
                                "image_hash": "blah",
                                "original_file_name": "blah",
                            },
                        },
                    }
                ],
                "processes": [
                    {
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": "blah",
                            "processtree": "blah",
                            "time_observed": "blah",
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": "blah",
                            "processtree": "blah",
                            "time_observed": "blah",
                        },
                        "pimage": "blah",
                        "pcommand_line": "blah",
                        "ppid": "blah",
                        "pid": "blah",
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": "blah",
                        "end_time": "blah",
                        "integrity_level": "blah",
                        "image_hash": "blah",
                        "original_file_name": "blah",
                    }
                ],
                "sandbox_name": "blah",
                "sandbox_version": "blah",
            }
        )

        assert default_so.analysis_metadata.task_id == "blah"
        assert default_so.analysis_metadata.start_time == "blah"
        assert default_so.analysis_metadata.end_time == "blah"
        assert default_so.analysis_metadata.routing == "blah"

        assert default_so.analysis_metadata.machine_metadata.ip == "blah"
        assert default_so.analysis_metadata.machine_metadata.hypervisor == "blah"
        assert default_so.analysis_metadata.machine_metadata.hostname == "blah"
        assert default_so.analysis_metadata.machine_metadata.platform == "blah"
        assert default_so.analysis_metadata.machine_metadata.version == "blah"
        assert default_so.analysis_metadata.machine_metadata.architecture == "blah"

        assert default_so.signatures[0].name == "blah"
        assert default_so.signatures[0].description == "blah"
        assert default_so.signatures[0].attack == ["blah"]

        assert default_so.signatures[0].subjects[0].ip == "blah"
        assert default_so.signatures[0].subjects[0].domain is None
        assert default_so.signatures[0].subjects[0].uri is None
        assert default_so.signatures[0].subjects[0].process is None
        assert default_so.signatures[0].subjects[0].file is None
        assert default_so.signatures[0].subjects[0].registry is None

        assert default_so.signatures[0].subjects[1].ip is None
        assert default_so.signatures[0].subjects[1].domain is None
        assert default_so.signatures[0].subjects[1].uri is None
        assert default_so.signatures[0].subjects[1].file is None
        assert default_so.signatures[0].subjects[1].registry is None

        assert (
            default_so.signatures[0].subjects[1].process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert default_so.signatures[0].subjects[1].process.objectid.tag == "blah"
        assert default_so.signatures[0].subjects[1].process.objectid.treeid == "blah"
        assert (
            default_so.signatures[0].subjects[1].process.objectid.time_observed
            == "blah"
        )
        assert (
            default_so.signatures[0].subjects[1].process.pobjectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert default_so.signatures[0].subjects[1].process.pobjectid.tag == "blah"
        assert default_so.signatures[0].subjects[1].process.pobjectid.treeid == "blah"
        assert default_so.signatures[0].subjects[1].process.pobjectid.processtree == "blah"
        assert (
            default_so.signatures[0].subjects[1].process.pobjectid.time_observed
            == "blah"
        )
        assert default_so.signatures[0].subjects[1].process.pimage == "blah"
        assert default_so.signatures[0].subjects[1].process.pcommand_line == "blah"
        assert default_so.signatures[0].subjects[1].process.ppid == "blah"
        assert default_so.signatures[0].subjects[1].process.pid == "blah"
        assert default_so.signatures[0].subjects[1].process.image == "blah"
        assert default_so.signatures[0].subjects[1].process.command_line == "blah"
        assert default_so.signatures[0].subjects[1].process.start_time == "blah"
        assert default_so.signatures[0].subjects[1].process.end_time == "blah"
        assert default_so.signatures[0].subjects[1].process.integrity_level == "blah"
        assert default_so.signatures[0].subjects[1].process.image_hash == "blah"
        assert default_so.signatures[0].subjects[1].process.original_file_name == "blah"

        assert (
            default_so.signatures[0].process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert default_so.signatures[0].process.objectid.tag == "blah"
        assert default_so.signatures[0].process.objectid.treeid == "blah"
        assert default_so.signatures[0].process.objectid.time_observed == "blah"
        assert (
            default_so.signatures[0].process.pobjectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert default_so.signatures[0].process.pobjectid.tag == "blah"
        assert default_so.signatures[0].process.pobjectid.treeid == "blah"
        assert default_so.signatures[0].process.pobjectid.processtree == "blah"
        assert default_so.signatures[0].process.pobjectid.time_observed == "blah"
        assert default_so.signatures[0].process.pimage == "blah"
        assert default_so.signatures[0].process.pcommand_line == "blah"
        assert default_so.signatures[0].process.ppid == "blah"
        assert default_so.signatures[0].process.pid == "blah"
        assert default_so.signatures[0].process.image == "blah"
        assert default_so.signatures[0].process.command_line == "blah"
        assert default_so.signatures[0].process.start_time == "blah"
        assert default_so.signatures[0].process.end_time == "blah"
        assert default_so.signatures[0].process.integrity_level == "blah"
        assert default_so.signatures[0].process.image_hash == "blah"
        assert default_so.signatures[0].process.original_file_name == "blah"

        assert str(UUID(
            default_so.network_connections[0].objectid.guid
        ))
        assert default_so.network_connections[0].objectid.tag == "blah"
        assert default_so.network_connections[0].objectid.treeid == "blah"
        assert default_so.network_connections[0].objectid.processtree == "blah"
        assert default_so.network_connections[0].objectid.time_observed == "blah"
        assert default_so.network_connections[0].source_ip == "blah"
        assert default_so.network_connections[0].source_port == "blah"
        assert default_so.network_connections[0].destination_ip == "blah"
        assert default_so.network_connections[0].destination_port == "blah"
        assert default_so.network_connections[0].transport_layer_protocol == "blah"
        assert default_so.network_connections[0].direction == "blah"

        assert (
            default_so.network_connections[0].process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert default_so.network_connections[0].process.objectid.tag == "blah"
        assert default_so.network_connections[0].process.objectid.treeid == "blah"
        assert default_so.network_connections[0].process.objectid.processtree == "blah"
        assert (
            default_so.network_connections[0].process.objectid.time_observed == "blah"
        )
        assert (
            default_so.network_connections[0].process.pobjectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert default_so.network_connections[0].process.pobjectid.tag == "blah"
        assert default_so.network_connections[0].process.pobjectid.treeid == "blah"
        assert default_so.network_connections[0].process.pobjectid.processtree == "blah"
        assert (
            default_so.network_connections[0].process.pobjectid.time_observed == "blah"
        )
        assert default_so.network_connections[0].process.pimage == "blah"
        assert default_so.network_connections[0].process.pcommand_line == "blah"
        assert default_so.network_connections[0].process.ppid == "blah"
        assert default_so.network_connections[0].process.pid == "blah"
        assert default_so.network_connections[0].process.image == "blah"
        assert default_so.network_connections[0].process.command_line == "blah"
        assert default_so.network_connections[0].process.start_time == "blah"
        assert default_so.network_connections[0].process.end_time == "blah"
        assert default_so.network_connections[0].process.integrity_level == "blah"
        assert default_so.network_connections[0].process.image_hash == "blah"
        assert default_so.network_connections[0].process.original_file_name == "blah"

        assert default_so.network_dns[0].domain == "blah"
        assert default_so.network_dns[0].resolved_ips == ["blah"]
        assert default_so.network_dns[0].lookup_type == "blah"

        assert str(UUID(
            default_so.network_dns[0].connection_details.objectid.guid
        ))
        assert default_so.network_dns[0].connection_details.objectid.tag == "blah"
        assert default_so.network_dns[0].connection_details.objectid.treeid == "blah"
        assert default_so.network_dns[0].connection_details.objectid.processtree == "blah"
        assert (
            default_so.network_dns[0].connection_details.objectid.time_observed
            == "blah"
        )
        assert default_so.network_dns[0].connection_details.source_ip == "blah"
        assert default_so.network_dns[0].connection_details.source_port == "blah"
        assert default_so.network_dns[0].connection_details.destination_ip == "blah"
        assert default_so.network_dns[0].connection_details.destination_port == "blah"
        assert (
            default_so.network_dns[0].connection_details.transport_layer_protocol
            == "blah"
        )
        assert default_so.network_dns[0].connection_details.direction == "blah"

        assert (
            default_so.network_dns[0].connection_details.process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert (
            default_so.network_dns[0].connection_details.process.objectid.tag == "blah"
        )
        assert (
            default_so.network_dns[0].connection_details.process.objectid.treeid
            == "blah"
        )
        assert (
            default_so.network_dns[0].connection_details.process.objectid.processtree
            == "blah"
        )
        assert (
            default_so.network_dns[0].connection_details.process.objectid.time_observed
            == "blah"
        )
        assert (
            default_so.network_dns[0].connection_details.process.pobjectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert (
            default_so.network_dns[0].connection_details.process.pobjectid.tag == "blah"
        )
        assert (
            default_so.network_dns[0].connection_details.process.pobjectid.treeid
            == "blah"
        )
        assert (
            default_so.network_dns[0].connection_details.process.pobjectid.processtree
            == "blah"
        )
        assert (
            default_so.network_dns[0].connection_details.process.pobjectid.time_observed
            == "blah"
        )
        assert default_so.network_dns[0].connection_details.process.pimage == "blah"
        assert (
            default_so.network_dns[0].connection_details.process.pcommand_line == "blah"
        )
        assert default_so.network_dns[0].connection_details.process.ppid == "blah"
        assert default_so.network_dns[0].connection_details.process.pid == "blah"
        assert default_so.network_dns[0].connection_details.process.image == "blah"
        assert (
            default_so.network_dns[0].connection_details.process.command_line == "blah"
        )
        assert default_so.network_dns[0].connection_details.process.start_time == "blah"
        assert default_so.network_dns[0].connection_details.process.end_time == "blah"
        assert (
            default_so.network_dns[0].connection_details.process.integrity_level
            == "blah"
        )
        assert default_so.network_dns[0].connection_details.process.image_hash == "blah"
        assert (
            default_so.network_dns[0].connection_details.process.original_file_name
            == "blah"
        )

        assert default_so.network_http[0].request_uri == "blah"
        assert default_so.network_http[0].request_headers == {"a": "b"}
        assert default_so.network_http[0].request_body == "blah"
        assert default_so.network_http[0].request_method == "blah"
        assert default_so.network_http[0].response_headers == {"a": "b"}
        assert default_so.network_http[0].response_status_code == 123
        assert default_so.network_http[0].response_body == "blah"

        assert str(UUID(
            default_so.network_http[0].connection_details.objectid.guid
        ))
        assert default_so.network_http[0].connection_details.objectid.tag == "blah"
        assert default_so.network_http[0].connection_details.objectid.treeid == "blah"
        assert default_so.network_http[0].connection_details.objectid.processtree == "blah"
        assert (
            default_so.network_http[0].connection_details.objectid.time_observed
            == "blah"
        )
        assert default_so.network_http[0].connection_details.source_ip == "blah"
        assert default_so.network_http[0].connection_details.source_port == "blah"
        assert default_so.network_http[0].connection_details.destination_ip == "blah"
        assert default_so.network_http[0].connection_details.destination_port == "blah"
        assert (
            default_so.network_http[0].connection_details.transport_layer_protocol
            == "blah"
        )
        assert default_so.network_http[0].connection_details.direction == "blah"

        assert (
            default_so.network_http[0].connection_details.process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert (
            default_so.network_http[0].connection_details.process.objectid.tag == "blah"
        )
        assert (
            default_so.network_http[0].connection_details.process.objectid.treeid
            == "blah"
        )
        assert (
            default_so.network_http[0].connection_details.process.objectid.processtree
            == "blah"
        )
        assert (
            default_so.network_http[0].connection_details.process.objectid.time_observed
            == "blah"
        )
        assert (
            default_so.network_http[0].connection_details.process.pobjectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert (
            default_so.network_http[0].connection_details.process.pobjectid.tag
            == "blah"
        )
        assert (
            default_so.network_http[0].connection_details.process.pobjectid.treeid
            == "blah"
        )
        assert (
            default_so.network_http[0].connection_details.process.pobjectid.processtree
            == "blah"
        )
        assert (
            default_so.network_http[
                0
            ].connection_details.process.pobjectid.time_observed
            == "blah"
        )
        assert default_so.network_http[0].connection_details.process.pimage == "blah"
        assert (
            default_so.network_http[0].connection_details.process.pcommand_line
            == "blah"
        )
        assert default_so.network_http[0].connection_details.process.ppid == "blah"
        assert default_so.network_http[0].connection_details.process.pid == "blah"
        assert default_so.network_http[0].connection_details.process.image == "blah"
        assert (
            default_so.network_http[0].connection_details.process.command_line == "blah"
        )
        assert (
            default_so.network_http[0].connection_details.process.start_time == "blah"
        )
        assert default_so.network_http[0].connection_details.process.end_time == "blah"
        assert (
            default_so.network_http[0].connection_details.process.integrity_level
            == "blah"
        )
        assert (
            default_so.network_http[0].connection_details.process.image_hash == "blah"
        )
        assert (
            default_so.network_http[0].connection_details.process.original_file_name
            == "blah"
        )

        assert (
            default_so.processes[0].objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert default_so.processes[0].objectid.tag == "blah"
        assert default_so.processes[0].objectid.treeid == "blah"
        assert default_so.processes[0].objectid.processtree == "blah"
        assert default_so.processes[0].objectid.time_observed == "blah"
        assert (
            default_so.processes[0].pobjectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert default_so.processes[0].pobjectid.tag == "blah"
        assert default_so.processes[0].pobjectid.treeid == "blah"
        assert default_so.processes[0].pobjectid.processtree == "blah"
        assert default_so.processes[0].pobjectid.time_observed == "blah"
        assert default_so.processes[0].pimage == "blah"
        assert default_so.processes[0].pcommand_line == "blah"
        assert default_so.processes[0].ppid == "blah"
        assert default_so.processes[0].pid == "blah"
        assert default_so.processes[0].image == "blah"
        assert default_so.processes[0].command_line == "blah"
        assert default_so.processes[0].start_time == "blah"
        assert default_so.processes[0].end_time == "blah"
        assert default_so.processes[0].integrity_level == "blah"
        assert default_so.processes[0].image_hash == "blah"
        assert default_so.processes[0].original_file_name == "blah"

        assert default_so.sandbox_name == "blah"
        assert default_so.sandbox_version == "blah"

    @staticmethod
    @pytest.mark.parametrize(
        "artifact_list, expected_result",
        [
            (None, None),
            ([], None),
            (
                [
                    {
                        "name": "blah",
                        "path": "blah",
                        "description": "blah",
                        "to_be_extracted": True,
                    }
                ],
                None,
            ),
            (
                [
                    {
                        "name": "blah",
                        "path": "blah",
                        "description": "blah",
                        "to_be_extracted": False,
                    }
                ],
                None,
            ),
        ],
    )
    def test_handle_artifacts(artifact_list, expected_result, dummy_request_class):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        r = dummy_request_class()
        o = SandboxOntology()
        actual_result = o.handle_artifacts(artifact_list, r)
        assert actual_result == expected_result

    @staticmethod
    def test_get_guids():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        p = so.create_process(
            pid=1,
            start_time=0.0,
            end_time=1.0,
            guid="{12345678-1234-5678-1234-567812345678}",
        )
        so.add_process(p)
        assert so._get_guids() == ["{12345678-1234-5678-1234-567812345678}"]

    @staticmethod
    def test_validate_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        so = SandboxOntology()

        # if not p.guid and p.pid not in pids:
        p1 = so.create_process(pid=1, start_time=0.0, end_time=1.0)
        assert so._validate_process(p1)
        assert UUID(p1.objectid.guid)
        so.add_process(p1)

        # else
        p2 = so.create_process(
            pid=2,
            start_time=0.0,
            end_time=1.0,
            guid="{12345678-1234-5678-1234-567812345678}",
        )
        assert so._validate_process(p2)
        so.add_process(p2)

        # elif p.guid in guids and p.pid in pids:
        p3 = so.create_process(
            pid=2,
            start_time=0.0,
            end_time=1.0,
            guid="{12345678-1234-5678-1234-567812345678}",
        )
        assert not so._validate_process(p3)

        # elif p.guid in guids and p.pid not in pids:
        p4 = so.create_process(
            pid=4,
            start_time=0.0,
            end_time=1.0,
            guid="{12345678-1234-5678-1234-567812345678}",
        )
        assert not so._validate_process(p4)

        # elif p.guid not in guids and p.pid in pids:
        p5 = so.create_process(
            pid=3,
            start_time=1.0,
            end_time=2.0,
            guid="{87654321-1234-5678-1234-567812345678}",
        )
        assert so._validate_process(p5)

    @staticmethod
    def test_handle_pid_match():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()

        # Test where no process is added
        p1 = so.create_process(pid=1, start_time=1.0, end_time=2.0)
        assert so._handle_pid_match(p1)
        so.add_process(p1)
        assert len(so.processes) == 1

        # Test where duplicate entry
        p2 = so.create_process(pid=1, start_time=1.0, end_time=2.0)
        assert not so._handle_pid_match(p2)

        # Test with valid start time
        p3 = so.create_process(pid=1, start_time=2.0, end_time=3.0)
        assert so._handle_pid_match(p3)
        so.add_process(p3)
        assert len(so.processes) == 2

        # Test with valid end time
        p4 = so.create_process(pid=1, start_time=0.0, end_time=1.0)
        assert so._handle_pid_match(p4)
        so.add_process(p4)
        assert len(so.processes) == 3

        # Test invalid entry
        p5 = so.create_process(pid=1, start_time=0.0, end_time=3.0)
        assert not so._handle_pid_match(p5)

    @staticmethod
    def test_remove_process():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        p = default_so.create_process()
        default_so.add_process(p)
        assert default_so.get_processes() == [p]
        p1 = default_so.create_process()
        default_so._remove_process(p1)
        assert default_so.get_processes() == [p]
        default_so._remove_process(p)
        assert default_so.get_processes() == []

    @staticmethod
    def test_remove_network_http():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nh = default_so.create_network_http()
        default_so.add_network_http(nh)
        assert default_so.get_network_http() == [nh]
        nh1 = default_so.create_network_http()
        default_so._remove_network_http(nh1)
        assert default_so.get_network_http() == [nh]
        default_so._remove_network_http(nh)
        assert default_so.get_network_http() == []

    @staticmethod
    def test_remove_network_dns():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nd = default_so.create_network_dns()
        default_so.add_network_dns(nd)
        assert default_so.get_network_dns() == [nd]
        nd1 = default_so.create_network_dns()
        default_so._remove_network_dns(nd1)
        assert default_so.get_network_dns() == [nd]
        default_so._remove_network_dns(nd)
        assert default_so.get_network_dns() == []

    @staticmethod
    def test_remove_network_connection():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        nc = default_so.create_network_connection()
        default_so.add_network_connection(nc)
        assert default_so.get_network_connections() == [nc]
        nc1 = default_so.create_network_connection()
        default_so._remove_network_connection(nc1)
        assert default_so.get_network_connections() == [nc]
        default_so._remove_network_connection(nc)
        assert default_so.get_network_connections() == []

    @staticmethod
    def test_remove_signature():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        signature = default_so.create_signature(name="blah")
        default_so.add_signature(signature)
        assert default_so.get_signatures() == [signature]
        signature1 = default_so.create_signature()
        default_so._remove_signature(signature1)
        assert default_so.get_signatures() == [signature]
        default_so._remove_signature(signature)
        assert default_so.get_signatures() == []

    @staticmethod
    def test_load_process_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        p = default_so._load_process_from_json(
            {
                "objectid": {
                    "guid": "{12345678-1234-5678-1234-567812345678}",
                    "tag": "blah",
                    "treeid": "blah",
                    "processtree": "blah",
                    "time_observed": "blah",
                },
                "pobjectid": {
                    "guid": "{12345678-1234-5678-1234-567812345678}",
                    "tag": "blah",
                    "treeid": "blah",
                    "processtree": "blah",
                    "time_observed": "blah",
                },
                "pimage": "blah",
                "pcommand_line": "blah",
                "ppid": "blah",
                "pid": "blah",
                "image": "blah",
                "command_line": "blah",
                "start_time": "blah",
                "end_time": "blah",
            }
        )
        assert p.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert p.objectid.tag == "blah"
        assert p.objectid.treeid == "blah"
        assert p.objectid.processtree == "blah"
        assert p.objectid.time_observed == "blah"
        assert p.pobjectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert p.pobjectid.tag == "blah"
        assert p.pobjectid.treeid == "blah"
        assert p.pobjectid.processtree == "blah"
        assert p.pobjectid.time_observed == "blah"
        assert p.pimage == "blah"
        assert p.pcommand_line == "blah"
        assert p.ppid == "blah"
        assert p.pid == "blah"
        assert p.image == "blah"
        assert p.command_line == "blah"
        assert p.start_time == "blah"
        assert p.end_time == "blah"

    @staticmethod
    def test_load_signature_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        s = default_so._load_signature_from_json(
            {
                "name": "blah",
                "description": "blah",
                "attack": [
                    {
                        "attack_id": "T1187",
                        "categories": ["credential-access"],
                        "pattern": "Forced Authentication",
                    }
                ],
                "subjects": [
                    {
                        "ip": "blah",
                        "domain": None,
                        "uri": None,
                        "process": None,
                        "file": None,
                        "registry": None,
                    },
                    {
                        "ip": "blah",
                        "domain": None,
                        "uri": None,
                        "process": {
                            "objectid": {
                                "guid": "{12345678-1234-5678-1234-567812345678}",
                                "tag": "blah",
                                "treeid": "blah",
                                "processtree": "blah",
                                "time_observed": "blah",
                            },
                            "pobjectid": {
                                "guid": "{12345678-1234-5678-1234-567812345678}",
                                "tag": "blah",
                                "treeid": "blah",
                                "processtree": "blah",
                                "time_observed": "blah",
                            },
                            "pimage": "blah",
                            "pcommand_line": "blah",
                            "ppid": "blah",
                            "pid": "blah",
                            "image": "blah",
                            "command_line": "blah",
                            "start_time": "blah",
                            "end_time": "blah",
                        },
                        "file": None,
                        "registry": None,
                    },
                ],
                "process": {
                    "objectid": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "tag": "blah",
                        "treeid": "blah",
                        "processtree": "blah",
                        "time_observed": "blah",
                    },
                    "pobjectid": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "tag": "blah",
                        "treeid": "blah",
                        "processtree": "blah",
                        "time_observed": "blah",
                    },
                    "pimage": "blah",
                    "pcommand_line": "blah",
                    "ppid": "blah",
                    "pid": "blah",
                    "image": "blah",
                    "command_line": "blah",
                    "start_time": "blah",
                    "end_time": "blah",
                },
            }
        )
        assert s.name == "blah"
        assert s.description == "blah"
        assert s.attack == [
            {
                "attack_id": "T1187",
                "categories": ["credential-access"],
                "pattern": "Forced Authentication",
            }
        ]
        assert s.subjects[0].ip == "blah"
        assert s.subjects[0].domain is None
        assert s.subjects[0].uri is None
        assert s.subjects[0].process is None
        assert s.subjects[0].file is None
        assert s.subjects[0].registry is None
        assert s.subjects[1].ip is None
        assert s.subjects[1].domain is None
        assert s.subjects[1].uri is None
        assert s.subjects[1].file is None
        assert s.subjects[1].registry is None
        assert (
            s.subjects[1].process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert s.subjects[1].process.objectid.tag == "blah"
        assert s.subjects[1].process.objectid.treeid == "blah"
        assert s.subjects[1].process.objectid.processtree == "blah"
        assert s.subjects[1].process.objectid.time_observed == "blah"
        assert (
            s.subjects[1].process.pobjectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert s.subjects[1].process.pobjectid.tag == "blah"
        assert s.subjects[1].process.pobjectid.treeid == "blah"
        assert s.subjects[1].process.pobjectid.processtree == "blah"
        assert s.subjects[1].process.pobjectid.time_observed == "blah"
        assert s.subjects[1].process.pimage == "blah"
        assert s.subjects[1].process.pcommand_line == "blah"
        assert s.subjects[1].process.ppid == "blah"
        assert s.subjects[1].process.pid == "blah"
        assert s.subjects[1].process.image == "blah"
        assert s.subjects[1].process.command_line == "blah"
        assert s.subjects[1].process.start_time == "blah"
        assert s.subjects[1].process.end_time == "blah"
        assert s.process.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert s.process.objectid.tag == "blah"
        assert s.process.objectid.treeid == "blah"
        assert s.process.objectid.processtree == "blah"
        assert s.process.objectid.time_observed == "blah"
        assert s.process.pobjectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert s.process.pobjectid.tag == "blah"
        assert s.process.pobjectid.treeid == "blah"
        assert s.process.pobjectid.processtree == "blah"
        assert s.process.pobjectid.time_observed == "blah"
        assert s.process.pimage == "blah"
        assert s.process.pcommand_line == "blah"
        assert s.process.ppid == "blah"
        assert s.process.pid == "blah"
        assert s.process.image == "blah"
        assert s.process.command_line == "blah"
        assert s.process.start_time == "blah"
        assert s.process.end_time == "blah"

    @staticmethod
    def test_load_network_connection_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        default_so = SandboxOntology()
        nc = default_so._load_network_connection_from_json(
            {
                "objectid": {
                    "tag": "blah",
                    "treeid": "blah",
                    "processtree": "blah",
                    "time_observed": "blah",
                },
                "source_ip": "blah",
                "source_port": "blah",
                "destination_ip": "blah",
                "destination_port": "blah",
                "transport_layer_protocol": "blah",
                "direction": "blah",
                "process": {
                    "objectid": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "tag": "blah",
                        "treeid": "blah",
                        "processtree": "blah",
                        "time_observed": "blah",
                    },
                    "pobjectid": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "tag": "blah",
                        "treeid": "blah",
                        "processtree": "blah",
                        "time_observed": "blah",
                    },
                    "pimage": "blah",
                    "pcommand_line": "blah",
                    "ppid": "blah",
                    "pid": "blah",
                    "image": "blah",
                    "command_line": "blah",
                    "start_time": "blah",
                    "end_time": "blah",
                    "integrity_level": "blah",
                    "image_hash": "blah",
                    "original_file_name": "blah",
                },
            }
        )
        assert str(UUID(nc.objectid.guid))
        assert nc.objectid.tag == "blah"
        assert nc.objectid.treeid == "blah"
        assert nc.objectid.processtree == "blah"
        assert nc.objectid.time_observed == "blah"
        assert nc.source_ip == "blah"
        assert nc.source_port == "blah"
        assert nc.destination_ip == "blah"
        assert nc.destination_port == "blah"
        assert nc.transport_layer_protocol == "blah"
        assert nc.direction == "blah"
        assert nc.process.objectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert nc.process.objectid.tag == "blah"
        assert nc.process.objectid.treeid == "blah"
        assert nc.process.objectid.processtree == "blah"
        assert nc.process.objectid.time_observed == "blah"
        assert nc.process.pobjectid.guid == "{12345678-1234-5678-1234-567812345678}"
        assert nc.process.pobjectid.tag == "blah"
        assert nc.process.pobjectid.treeid == "blah"
        assert nc.process.pobjectid.processtree == "blah"
        assert nc.process.pobjectid.time_observed == "blah"
        assert nc.process.pimage == "blah"
        assert nc.process.pcommand_line == "blah"
        assert nc.process.ppid == "blah"
        assert nc.process.pid == "blah"
        assert nc.process.image == "blah"
        assert nc.process.command_line == "blah"
        assert nc.process.start_time == "blah"
        assert nc.process.end_time == "blah"
        assert nc.process.integrity_level == "blah"
        assert nc.process.image_hash == "blah"
        assert nc.process.original_file_name == "blah"

    @staticmethod
    def test_load_network_dns_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        default_so = SandboxOntology()
        nd = default_so._load_network_dns_from_json(
            {
                "domain": "blah",
                "resolved_ips": ["blah"],
                "lookup_type": "blah",
                "connection_details": {
                    "objectid": {
                        "tag": "blah",
                        "treeid": "blah",
                        "processtree": "blah",
                        "time_observed": "blah",
                    },
                    "source_ip": "blah",
                    "source_port": "blah",
                    "destination_ip": "blah",
                    "destination_port": "blah",
                    "transport_layer_protocol": "blah",
                    "direction": "blah",
                    "process": {
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": "blah",
                            "processtree": "blah",
                            "time_observed": "blah",
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": "blah",
                            "processtree": "blah",
                            "time_observed": "blah",
                        },
                        "pimage": "blah",
                        "pcommand_line": "blah",
                        "ppid": "blah",
                        "pid": "blah",
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": "blah",
                        "end_time": "blah",
                        "integrity_level": "blah",
                        "image_hash": "blah",
                        "original_file_name": "blah",
                    },
                },
            }
        )
        assert nd.domain == "blah"
        assert nd.resolved_ips == ["blah"]
        assert nd.lookup_type == "blah"
        assert str(UUID(
            nd.connection_details.objectid.guid
        ))
        assert nd.connection_details.objectid.tag == "blah"
        assert nd.connection_details.objectid.treeid == "blah"
        assert nd.connection_details.objectid.processtree == "blah"
        assert nd.connection_details.objectid.time_observed == "blah"
        assert nd.connection_details.source_ip == "blah"
        assert nd.connection_details.source_port == "blah"
        assert nd.connection_details.destination_ip == "blah"
        assert nd.connection_details.destination_port == "blah"
        assert nd.connection_details.transport_layer_protocol == "blah"
        assert nd.connection_details.direction == "blah"
        assert (
            nd.connection_details.process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert nd.connection_details.process.objectid.tag == "blah"
        assert nd.connection_details.process.objectid.treeid == "blah"
        assert nd.connection_details.process.objectid.processtree == "blah"
        assert nd.connection_details.process.objectid.time_observed == "blah"
        assert (
            nd.connection_details.process.pobjectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert nd.connection_details.process.pobjectid.tag == "blah"
        assert nd.connection_details.process.pobjectid.treeid == "blah"
        assert nd.connection_details.process.pobjectid.processtree == "blah"
        assert nd.connection_details.process.pobjectid.time_observed == "blah"
        assert nd.connection_details.process.pimage == "blah"
        assert nd.connection_details.process.pcommand_line == "blah"
        assert nd.connection_details.process.ppid == "blah"
        assert nd.connection_details.process.pid == "blah"
        assert nd.connection_details.process.image == "blah"
        assert nd.connection_details.process.command_line == "blah"
        assert nd.connection_details.process.start_time == "blah"
        assert nd.connection_details.process.end_time == "blah"
        assert nd.connection_details.process.integrity_level == "blah"
        assert nd.connection_details.process.image_hash == "blah"
        assert nd.connection_details.process.original_file_name == "blah"

    @staticmethod
    def test_load_network_http_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )
        from uuid import UUID

        default_so = SandboxOntology()
        nh = default_so._load_network_http_from_json(
            {
                "request_uri": "blah",
                "request_headers": {"a": "b"},
                "request_body": "blah",
                "request_method": "blah",
                "response_headers": {"a": "b"},
                "response_status_code": 123,
                "response_body": "blah",
                "connection_details": {
                    "objectid": {
                        "tag": "blah",
                        "treeid": "blah",
                        "processtree": "blah",
                        "time_observed": "blah",
                    },
                    "source_ip": "blah",
                    "source_port": "blah",
                    "destination_ip": "blah",
                    "destination_port": "blah",
                    "transport_layer_protocol": "blah",
                    "direction": "blah",
                    "process": {
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": "blah",
                            "processtree": "blah",
                            "time_observed": "blah",
                        },
                        "pobjectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": "blah",
                            "processtree": "blah",
                            "time_observed": "blah",
                        },
                        "pimage": "blah",
                        "pcommand_line": "blah",
                        "ppid": "blah",
                        "pid": "blah",
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": "blah",
                        "end_time": "blah",
                        "integrity_level": "blah",
                        "image_hash": "blah",
                        "original_file_name": "blah",
                    },
                },
            }
        )
        assert nh.request_uri == "blah"
        assert nh.request_headers == {"a": "b"}
        assert nh.request_method == "blah"
        assert nh.response_status_code == 123
        assert nh.response_body == "blah"
        assert str(UUID(
            nh.connection_details.objectid.guid
        ))
        assert nh.connection_details.objectid.tag == "blah"
        assert nh.connection_details.objectid.treeid == "blah"
        assert nh.connection_details.objectid.processtree == "blah"
        assert nh.connection_details.objectid.time_observed == "blah"
        assert nh.connection_details.source_ip == "blah"
        assert nh.connection_details.source_port == "blah"
        assert nh.connection_details.destination_ip == "blah"
        assert nh.connection_details.destination_port == "blah"
        assert nh.connection_details.transport_layer_protocol == "blah"
        assert nh.connection_details.direction == "blah"
        assert (
            nh.connection_details.process.objectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert nh.connection_details.process.objectid.tag == "blah"
        assert nh.connection_details.process.objectid.treeid == "blah"
        assert nh.connection_details.process.objectid.processtree == "blah"
        assert nh.connection_details.process.objectid.time_observed == "blah"
        assert (
            nh.connection_details.process.pobjectid.guid
            == "{12345678-1234-5678-1234-567812345678}"
        )
        assert nh.connection_details.process.pobjectid.tag == "blah"
        assert nh.connection_details.process.pobjectid.treeid == "blah"
        assert nh.connection_details.process.pobjectid.processtree == "blah"
        assert nh.connection_details.process.pobjectid.time_observed == "blah"
        assert nh.connection_details.process.pimage == "blah"
        assert nh.connection_details.process.pcommand_line == "blah"
        assert nh.connection_details.process.ppid == "blah"
        assert nh.connection_details.process.pid == "blah"
        assert nh.connection_details.process.image == "blah"
        assert nh.connection_details.process.command_line == "blah"
        assert nh.connection_details.process.start_time == "blah"
        assert nh.connection_details.process.end_time == "blah"
        assert nh.connection_details.process.integrity_level == "blah"
        assert nh.connection_details.process.image_hash == "blah"
        assert nh.connection_details.process.original_file_name == "blah"

    @staticmethod
    @pytest.mark.parametrize(
        "things_to_sort_by_time_observed, expected_result",
        [
            (None, []),
            ([], []),
            (
                [{"objectid": {"time_observed": 1}}],
                [{"objectid": {"time_observed": 1}}],
            ),
            (
                [
                    {"objectid": {"time_observed": 1}},
                    {"objectid": {"time_observed": 2}},
                ],
                [
                    {"objectid": {"time_observed": 1}},
                    {"objectid": {"time_observed": 2}},
                ],
            ),
            (
                [
                    {"objectid": {"time_observed": 1}},
                    {"objectid": {"time_observed": 1}},
                ],
                [
                    {"objectid": {"time_observed": 1}},
                    {"objectid": {"time_observed": 1}},
                ],
            ),
            (
                [
                    {"objectid": {"time_observed": 2}},
                    {"objectid": {"time_observed": 1}},
                ],
                [
                    {"objectid": {"time_observed": 1}},
                    {"objectid": {"time_observed": 2}},
                ],
            ),
            (
                [
                    {"objectid": {"time_observed": 3}},
                    {"objectid": {"time_observed": 2}},
                    {"objectid": {"time_observed": 1}},
                ],
                [
                    {"objectid": {"time_observed": 1}},
                    {"objectid": {"time_observed": 2}},
                    {"objectid": {"time_observed": 3}},
                ],
            ),
        ],
    )
    def test_sort_things_by_time_observed(
        things_to_sort_by_time_observed, expected_result, dummy_timestamp_class
    ):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        dummy_things = []
        dummy_results = []
        if things_to_sort_by_time_observed is None:
            assert SandboxOntology._sort_things_by_time_observed(dummy_things) == []
            return

        actual_result = SandboxOntology._sort_things_by_time_observed(
            things_to_sort_by_time_observed
        )
        for index, item in enumerate(actual_result):
            assert item == expected_result[index]

        dummy_things = []
        dummy_results = []
        for thing in things_to_sort_by_time_observed:
            dummy_things.append(dummy_timestamp_class(thing))
        for result in expected_result:
            dummy_results.append(dummy_timestamp_class(result))
        actual_result = SandboxOntology._sort_things_by_time_observed(dummy_things)
        for index, item in enumerate(actual_result):
            assert (
                item.__dict__["objectid"].__dict__
                == dummy_results[index].__dict__["objectid"].__dict__
            )

    @staticmethod
    @pytest.mark.parametrize(
        "things_to_sort, expected_result",
        [
            (None, []),
            ([], []),
            # One item
            (
                [{"objectid": {"time_observed": 1, "guid": "a"}, "pobjectid": {"time_observed": 1, "guid": "b"}}],
                [{"objectid": {"time_observed": 1, "guid": "a"}, "pobjectid": {"time_observed": 1, "guid": "b"}}],
            ),
            # Two unrelated items, sorted by time
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "a"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 2, "guid": "b"}, "pobjectid": {"time_observed": 2, "guid": "d"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "a"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 2, "guid": "b"}, "pobjectid": {"time_observed": 2, "guid": "d"}},
                ],
            ),
            # Two unrelated items, not sorted by time
            (
                [
                    {"objectid": {"time_observed": 2, "guid": "b"}, "pobjectid": {"time_observed": 2, "guid": "d"}},
                    {"objectid": {"time_observed": 1, "guid": "a"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                ],
                [
                    {"objectid": {"time_observed": 2, "guid": "b"}, "pobjectid": {"time_observed": 2, "guid": "d"}},
                    {"objectid": {"time_observed": 1, "guid": "a"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                ],
            ),
            #  Two unrelated items, sharing the same times
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "a"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "d"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "a"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "d"}},
                ],
            ),
            # A parent-child relationship, sharing the same time, in the correct order
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                ],
            ),
            # A parent-child relationship, sharing the same time, in the incorrect order
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                ],
            ),
            # A parent-child relationship, sharing the same time, in the correct order, with a random item in-between
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "e"}, "pobjectid": {"time_observed": 1, "guid": "d"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "e"}, "pobjectid": {"time_observed": 1, "guid": "d"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                ],
            ),
            # A parent-child-child relationship, sharing the same time, in the incorrect order, with a random item in-between, parent at the bottom
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 2, "guid": "f"}, "pobjectid": {"time_observed": 2, "guid": "e"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 2, "guid": "f"}, "pobjectid": {"time_observed": 2, "guid": "e"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                ],
            ),
            # A parent-child-child relationship, sharing the same time, in the incorrect order, parent in the middle
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                ],
            ),
            # A grandparent-parent-child relationship, sharing the same time, in the incorrect order, in ascending order
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                ],
            ),
            # A grandparent-parent-child relationship, sharing the same time, in the incorrect order, in mismatched order
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                ],
            ),
            # A grandparent-parent-parent-child-child-child relationship, sharing the same time, in the incorrect order, in ascending order
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "g"}, "pobjectid": {"time_observed": 1, "guid": "d"}},
                    {"objectid": {"time_observed": 1, "guid": "f"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "e"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "g"}, "pobjectid": {"time_observed": 1, "guid": "d"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "f"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "e"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                ],
            ),
            # A grandparent-parent-parent-parent-child-child-child-random-random relationship, sharing the same time, in the incorrect order, in ascending order
            (
                [
                    {"objectid": {"time_observed": 1, "guid": "z"}, "pobjectid": {"time_observed": 1, "guid": "y"}},
                    {"objectid": {"time_observed": 1, "guid": "x"}, "pobjectid": {"time_observed": 1, "guid": "v"}},
                    {"objectid": {"time_observed": 1, "guid": "g"}, "pobjectid": {"time_observed": 1, "guid": "d"}},
                    {"objectid": {"time_observed": 1, "guid": "f"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "e"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "h"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                ],
                [
                    {"objectid": {"time_observed": 1, "guid": "z"}, "pobjectid": {"time_observed": 1, "guid": "y"}},
                    {"objectid": {"time_observed": 1, "guid": "x"}, "pobjectid": {"time_observed": 1, "guid": "v"}},
                    {"objectid": {"time_observed": 1, "guid": "b"}, "pobjectid": {"time_observed": 1, "guid": "a"}},
                    {"objectid": {"time_observed": 1, "guid": "d"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "g"}, "pobjectid": {"time_observed": 1, "guid": "d"}},
                    {"objectid": {"time_observed": 1, "guid": "c"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                    {"objectid": {"time_observed": 1, "guid": "f"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "e"}, "pobjectid": {"time_observed": 1, "guid": "c"}},
                    {"objectid": {"time_observed": 1, "guid": "h"}, "pobjectid": {"time_observed": 1, "guid": "b"}},
                ],
            ),
            # A grandparent-parent-child+parent-child+random relationship, sharing different times time, in the incorrect order, in mismatched order
            (
                [
                    {'objectid': {'guid': 'd', 'time_observed': float("-inf")},
                     'pobjectid': {'guid': 'c', 'time_observed': float("-inf")}},
                    {'objectid': {'guid': 'g', 'time_observed': float("-inf")},
                     'pobjectid': {'guid': 'f', 'time_observed': float("-inf")}},
                    {'objectid': {'guid': 'c', 'time_observed': float("-inf")},
                     'pobjectid': {'guid': 'b', 'time_observed': float("-inf")}},
                    {'objectid': {'guid': 'f', 'time_observed': float(
                        "-inf")}, 'pobjectid': {'guid': 'e', 'time_observed': None}},
                    {'objectid': {'guid': 'b', 'time_observed': float(
                        "-inf")}, 'pobjectid': {'guid': 'a', 'time_observed': None}},
                    {'objectid': {'guid': 'h', 'time_observed': float(
                        "-inf")}, 'pobjectid': {'guid': 'i', 'time_observed': None}}
                ],
                [
                    {'objectid': {'guid': 'b', 'time_observed': float(
                        "-inf")}, 'pobjectid': {'guid': 'a', 'time_observed': None}},
                    {'objectid': {'guid': 'c', 'time_observed': float("-inf")},
                     'pobjectid': {'guid': 'b', 'time_observed': float("-inf")}},
                    {'objectid': {'guid': 'd', 'time_observed': float("-inf")},
                     'pobjectid': {'guid': 'c', 'time_observed': float("-inf")}},
                    {'objectid': {'guid': 'f', 'time_observed': float(
                        "-inf")}, 'pobjectid': {'guid': 'e', 'time_observed': None}},
                    {'objectid': {'guid': 'g', 'time_observed': float("-inf")},
                     'pobjectid': {'guid': 'f', 'time_observed': float("-inf")}},
                    {'objectid': {'guid': 'h', 'time_observed': float(
                        "-inf")}, 'pobjectid': {'guid': 'i', 'time_observed': None}}
                ],
            )
        ],
    )
    def test_sort_things_by_relationship(
        things_to_sort, expected_result, dummy_timestamp_class
    ):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        dummy_things = []
        dummy_results = []
        if things_to_sort is None:
            assert SandboxOntology._sort_things_by_relationship(dummy_things) == []
            return

        actual_result = SandboxOntology._sort_things_by_relationship(
            things_to_sort
        )
        for index, item in enumerate(actual_result):
            assert item == expected_result[index]

        dummy_things = []
        dummy_results = []
        for thing in things_to_sort:
            dummy_things.append(dummy_timestamp_class(thing))
        for result in expected_result:
            dummy_results.append(dummy_timestamp_class(result))
        actual_result = SandboxOntology._sort_things_by_relationship(dummy_things)
        for index, item in enumerate(actual_result):
            assert (
                item.__dict__["objectid"].__dict__
                == dummy_results[index].__dict__["objectid"].__dict__
            )

    @staticmethod
    @pytest.mark.parametrize(
        "events, expected_events_dict",
        [
            (
                [
                    {
                        "pid": 1,
                        "image": "blah",
                        "start_time": 1,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                    }
                ],
                {
                    "{12345678-1234-5678-1234-567812345678}": {
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "pimage": None,
                        "pcommand_line": None,
                        "ppid": None,
                        "pid": 1,
                        "image": "blah",
                        "command_line": None,
                        "start_time": 1,
                        "end_time": None,
                        "integrity_level": None,
                        "image_hash": None,
                        "original_file_name": None,
                    }
                },
            ),
            ([{"pid": 1, "image": "blah", "start_time": 1, "guid": None}], {}),
            (
                [
                    {
                        "pid": 1,
                        "image": "blah",
                        "start_time": 1,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                    },
                    {
                        "pid": 2,
                        "image": "blah",
                        "start_time": 1,
                        "guid": "{12345678-1234-5678-1234-567812345679}",
                    },
                ],
                {
                    "{12345678-1234-5678-1234-567812345678}": {
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "pimage": None,
                        "pcommand_line": None,
                        "ppid": None,
                        "pid": 1,
                        "image": "blah",
                        "command_line": None,
                        "start_time": 1,
                        "end_time": None,
                        "integrity_level": None,
                        "image_hash": None,
                        "original_file_name": None,
                    },
                    "{12345678-1234-5678-1234-567812345679}": {
                        "objectid": {
                            "guid": "{12345678-1234-5678-1234-567812345679}",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "pimage": None,
                        "pcommand_line": None,
                        "ppid": None,
                        "pid": 2,
                        "image": "blah",
                        "command_line": None,
                        "start_time": 1,
                        "end_time": None,
                        "integrity_level": None,
                        "image_hash": None,
                        "original_file_name": None,
                    },
                },
            ),
        ],
    )
    def test_convert_events_to_dict(events, expected_events_dict):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
            Process,
        )

        event_objects = [
            Process(
                pid=event["pid"],
                image=event["image"],
                start_time=event["start_time"],
                guid=event["guid"],
            )
            for event in events
        ]
        assert (
            SandboxOntology._convert_events_to_dict(event_objects)
            == expected_events_dict
        )

    @staticmethod
    @pytest.mark.parametrize(
        "events_dict, expected_result",
        [
            # No processes
            ({}, []),
            # One process
            (
                {
                    "a": {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    }
                },
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "children": [],
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    }
                ],
            ),
            # One parent process and one child process
            (
                {
                    "a": {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "b": {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "b",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "a",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                },
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [
                            {
                                "pid": 2,
                                "ppid": 1,
                                "image": "blah",
                                "command_line": "blah",
                                "start_time": 1,
                                "objectid": {
                                    "guid": "b",
                                    "tag": "blah",
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 1,
                                },
                                "pobjectid": {
                                    "guid": "a",
                                    "tag": None,
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": None,
                                },
                                "children": [],
                            }
                        ],
                    },
                ],
            ),
            # Two unrelated processes
            (
                {
                    "a": {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "b": {
                        "pid": 2,
                        "ppid": 2,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "b",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                },
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [],
                    },
                    {
                        "pid": 2,
                        "ppid": 2,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "b",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [],
                    },
                ],
            ),
            # Three processes consisting of a parent-child relationship and a rando process
            (
                {
                    "a": {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "b": {
                        "pid": 2,
                        "ppid": 2,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "b",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "c": {
                        "pid": 3,
                        "ppid": 2,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "c",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "b",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                },
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [],
                    },
                    {
                        "pid": 2,
                        "ppid": 2,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "b",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [
                            {
                                "pid": 3,
                                "ppid": 2,
                                "image": "blah",
                                "command_line": "blah",
                                "start_time": 1,
                                "objectid": {
                                    "guid": "c",
                                    "tag": "blah",
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 1,
                                },
                                "pobjectid": {
                                    "guid": "b",
                                    "tag": None,
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": None,
                                },
                                "children": [],
                            }
                        ],
                    },
                ],
            ),
            # Three processes consisting of a grandparent-parent-child relationship and one rando process
            (
                {
                    "a": {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "b": {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 2,
                        "objectid": {
                            "guid": "b",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "a",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "c": {
                        "pid": 3,
                        "ppid": 2,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 3,
                        "objectid": {
                            "guid": "c",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": "b",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "d": {
                        "pid": 4,
                        "ppid": 4,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 2,
                        "objectid": {
                            "guid": "d",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                },
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [
                            {
                                "pid": 2,
                                "ppid": 1,
                                "image": "blah",
                                "command_line": "blah",
                                "start_time": 2,
                                "objectid": {
                                    "guid": "b",
                                    "tag": "blah",
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 1,
                                },
                                "pobjectid": {
                                    "guid": "a",
                                    "tag": None,
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": None,
                                },
                                "children": [
                                    {
                                        "pid": 3,
                                        "ppid": 2,
                                        "image": "blah",
                                        "command_line": "blah",
                                        "start_time": 3,
                                        "objectid": {
                                            "guid": "c",
                                            "tag": "blah",
                                            "treeid": None,
                                            "processtree": None,
                                            "time_observed": 1,
                                        },
                                        "pobjectid": {
                                            "guid": "b",
                                            "tag": None,
                                            "treeid": None,
                                            "processtree": None,
                                            "time_observed": None,
                                        },
                                        "children": [],
                                    },
                                ],
                            }
                        ],
                    },
                    {
                        "pid": 4,
                        "ppid": 4,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 2,
                        "objectid": {
                            "guid": "d",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [],
                    },
                ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship
            (
                {
                    "a": {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "b": {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 2,
                        "objectid": {
                            "guid": "b",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                        "pobjectid": {
                            "guid": "a",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "c": {
                        "pid": 3,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 3,
                        "objectid": {
                            "guid": "c",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 3,
                        },
                        "pobjectid": {
                            "guid": "a",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "d": {
                        "pid": 4,
                        "ppid": 2,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 4,
                        "objectid": {
                            "guid": "d",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 4,
                        },
                        "pobjectid": {
                            "guid": "b",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                },
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [
                            {
                                "pid": 2,
                                "ppid": 1,
                                "image": "blah",
                                "command_line": "blah",
                                "start_time": 2,
                                "objectid": {
                                    "guid": "b",
                                    "tag": "blah",
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 2,
                                },
                                "pobjectid": {
                                    "guid": "a",
                                    "tag": None,
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": None,
                                },
                                "children": [
                                    {
                                        "pid": 4,
                                        "ppid": 2,
                                        "image": "blah",
                                        "command_line": "blah",
                                        "start_time": 4,
                                        "objectid": {
                                            "guid": "d",
                                            "tag": "blah",
                                            "treeid": None,
                                            "processtree": None,
                                            "time_observed": 4,
                                        },
                                        "pobjectid": {
                                            "guid": "b",
                                            "tag": None,
                                            "treeid": None,
                                            "processtree": None,
                                            "time_observed": None,
                                        },
                                        "children": [],
                                    }
                                ],
                            },
                            {
                                "pid": 3,
                                "ppid": 1,
                                "image": "blah",
                                "command_line": "blah",
                                "start_time": 3,
                                "objectid": {
                                    "guid": "c",
                                    "tag": "blah",
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 3,
                                },
                                "pobjectid": {
                                    "guid": "a",
                                    "tag": None,
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": None,
                                },
                                "children": [],
                            },
                        ],
                    },
                ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship with non-ordered times
            (
                {
                    "a": {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "b": {
                        "pid": 2,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 3,
                        "objectid": {
                            "guid": "b",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 3,
                        },
                        "pobjectid": {
                            "guid": "a",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "c": {
                        "pid": 3,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 2,
                        "objectid": {
                            "guid": "c",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                        "pobjectid": {
                            "guid": "a",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "d": {
                        "pid": 4,
                        "ppid": 2,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 4,
                        "objectid": {
                            "guid": "d",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 4,
                        },
                        "pobjectid": {
                            "guid": "b",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                },
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [
                            {
                                "pid": 3,
                                "ppid": 1,
                                "image": "blah",
                                "command_line": "blah",
                                "start_time": 2,
                                "objectid": {
                                    "guid": "c",
                                    "tag": "blah",
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 2,
                                },
                                "pobjectid": {
                                    "guid": "a",
                                    "tag": None,
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": None,
                                },
                                "children": [],
                            },
                            {
                                "pid": 2,
                                "ppid": 1,
                                "image": "blah",
                                "command_line": "blah",
                                "start_time": 3,
                                "objectid": {
                                    "guid": "b",
                                    "tag": "blah",
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 3,
                                },
                                "pobjectid": {
                                    "guid": "a",
                                    "tag": None,
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": None,
                                },
                                "children": [
                                    {
                                        "pid": 4,
                                        "ppid": 2,
                                        "image": "blah",
                                        "command_line": "blah",
                                        "start_time": 4,
                                        "objectid": {
                                            "guid": "d",
                                            "tag": "blah",
                                            "treeid": None,
                                            "processtree": None,
                                            "time_observed": 4,
                                        },
                                        "pobjectid": {
                                            "guid": "b",
                                            "tag": None,
                                            "treeid": None,
                                            "processtree": None,
                                            "time_observed": None,
                                        },
                                        "children": [],
                                    }
                                ],
                            },
                        ],
                    },
                ],
            ),
            # One process and one unrelated network connection with no process
            (
                {
                    "a": {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "b": {
                        "process": None,
                        "source_ip": None,
                        "source_port": None,
                        "destination_ip": None,
                        "destination_port": None,
                        "transport_layer_protocol": None,
                        "direction": None,
                        "objectid": {
                            "guid": "b",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                    },
                },
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [],
                    },
                    {
                        "process": None,
                        "source_ip": None,
                        "source_port": None,
                        "destination_ip": None,
                        "destination_port": None,
                        "transport_layer_protocol": None,
                        "direction": None,
                        "objectid": {
                            "guid": "b",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                        "children": [],
                    },
                ],
            ),
            # One process and one child network connection
            (
                {
                    "a": {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "b": {
                        "process": {"objectid": {"guid": "a", "time_observed": 1}, "pobject": {"guid": "c", "time_observed": 0}},
                        "source_ip": None,
                        "source_port": None,
                        "destination_ip": None,
                        "destination_port": None,
                        "transport_layer_protocol": None,
                        "direction": None,
                        "objectid": {
                            "guid": "b",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                    },
                },
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [
                            {
                                "process": {"objectid": {"guid": "a", "time_observed": 1}, "pobject": {"guid": "c", "time_observed": 0}},
                                "source_ip": None,
                                "source_port": None,
                                "destination_ip": None,
                                "destination_port": None,
                                "transport_layer_protocol": None,
                                "direction": None,
                                "objectid": {
                                    "guid": "b",
                                    "tag": None,
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 2,
                                },
                                "children": [],
                            }
                        ],
                    }
                ],
            ),
            # One process and two child network connections, unordered times
            (
                {
                    "a": {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                    },
                    "b": {
                        "process": {"objectid": {"guid": "a", "time_observed": 1}, "pobject": {"guid": "c", "time_observed": 0}},
                        "source_ip": None,
                        "source_port": None,
                        "destination_ip": None,
                        "destination_port": None,
                        "transport_layer_protocol": None,
                        "direction": None,
                        "objectid": {
                            "guid": "b",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 3,
                        },
                    },
                    "c": {
                        "process": {"objectid": {"guid": "a", "time_observed": 1}, "pobject": {"guid": "c", "time_observed": 0}},
                        "source_ip": None,
                        "source_port": None,
                        "destination_ip": None,
                        "destination_port": None,
                        "transport_layer_protocol": None,
                        "direction": None,
                        "objectid": {
                            "guid": "c",
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 2,
                        },
                    },
                },
                [
                    {
                        "pid": 1,
                        "ppid": 1,
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": 1,
                        "objectid": {
                            "guid": "a",
                            "tag": "blah",
                            "treeid": None,
                            "processtree": None,
                            "time_observed": 1,
                        },
                        "pobjectid": {
                            "guid": None,
                            "tag": None,
                            "treeid": None,
                            "processtree": None,
                            "time_observed": None,
                        },
                        "children": [
                            {
                                "process": {"objectid": {"guid": "a", "time_observed": 1}, "pobject": {"guid": "c", "time_observed": 0}},
                                "source_ip": None,
                                "source_port": None,
                                "destination_ip": None,
                                "destination_port": None,
                                "transport_layer_protocol": None,
                                "direction": None,
                                "objectid": {
                                    "guid": "c",
                                    "tag": None,
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 2,
                                },
                                "children": [],
                            },
                            {
                                "process": {"objectid": {"guid": "a", "time_observed": 1}, "pobject": {"guid": "c", "time_observed": 0}},
                                "source_ip": None,
                                "source_port": None,
                                "destination_ip": None,
                                "destination_port": None,
                                "transport_layer_protocol": None,
                                "direction": None,
                                "objectid": {
                                    "guid": "b",
                                    "tag": None,
                                    "treeid": None,
                                    "processtree": None,
                                    "time_observed": 3,
                                },
                                "children": [],
                            },
                        ],
                    }
                ],
            ),
        ],
    )
    def test_convert_events_dict_to_tree(events_dict, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        actual_result = SandboxOntology._convert_events_dict_to_tree(events_dict)
        assert actual_result == expected_result

    @staticmethod
    def test_convert_event_tree_to_result_section():
        from assemblyline_v4_service.common.result import ResultProcessTreeSection
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        result_section = ResultProcessTreeSection("Spawned Process Tree")

        so = SandboxOntology()
        actual_items = []
        event = {
            "pid": 1,
            "image": "blah",
            "command_line": "blah",
            "objectid": {
                "treeid": "blahblah",
                "processtree": "blahblah",
            },
            "children": [
                {"process": {}, "objectid": {"processtree": "blahblahblah", "treeid": None}},
                {"pid": 2, "image": "blah", "command_line": "blah", "children": [], "objectid": {"processtree": "blahblahblahblah", "treeid": None}}
            ],
        }
        safelist = ["blahblah"]
        p = so.create_process(pid=2, start_time=1.0)
        so.add_process(p)
        sig = so.create_signature(process=p, name="bad", score=99)
        so.add_signature(sig)
        nc = so.create_network_connection(process=p, destination_ip="1.1.1.1")
        so.add_network_connection(nc)
        so._convert_event_tree_to_result_section(actual_items, event, safelist, result_section)
        assert actual_items[0].as_primitives() == {
            "process_name": "blah",
            "command_line": "blah",
            "process_pid": 1,
            "children": [
                {
                    "process_name": "blah",
                    "command_line": "blah",
                    "process_pid": 2,
                    "children": [],
                    "signatures": {"bad": 99},
                    "file_count": 0,
                    "network_count": 1,
                    "registry_count": 0,
                    "safelisted": False,
                }
            ],
            "signatures": {},
            "file_count": 0,
            "network_count": 0,
            "registry_count": 0,
            "safelisted": True,
        }
        assert result_section.tags == {"dynamic.processtree_id": ["blahblahblahblah"]}

    @staticmethod
    @pytest.mark.parametrize(
        "parent_treeid, parent_processtree, node, expected_node, expected_treeids, expected_processtrees",
        [
            (
                "",
                "",
                {
                    "objectid": {
                        "tag": "got the image",
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                    },
                    "children": [
                        {
                            "objectid": {
                                "tag": "image number 2",
                                "guid": "{12345678-1234-5678-1234-567812345679}",
                            },
                            "children": [],
                        },
                        {
                            "objectid": {
                                "tag": "image number 3",
                                "guid": "{12345678-1234-5678-1234-567812345670}",
                            },
                            "children": [],
                        },
                    ],
                },
                {
                    "objectid": {
                        "tag": "got the image",
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "treeid": "b71bf6eacf36ecdf07b3f1efa5d6f50725271ca85369b966e19da5b76c175b5b",
                        "processtree": "got the image",
                    },
                    "children": [
                        {
                            "objectid": {
                                "tag": "image number 2",
                                "treeid": "294156e02fb77c860933c93da8629dbceab367629a1ff9af68ff4b03c8596b17",
                                "processtree": "got the image|image number 2",
                                "guid": "{12345678-1234-5678-1234-567812345679}",
                            },
                            "children": [],
                        },
                        {
                            "objectid": {
                                "tag": "image number 3",
                                "treeid": "0483e740e929697527964c71227dd76403cdc91ca16e7a4a9a430f734481f129",
                                "processtree": "got the image|image number 3",
                                "guid": "{12345678-1234-5678-1234-567812345670}",
                            },
                            "children": [],
                        },
                    ],
                },
                [
                    "b71bf6eacf36ecdf07b3f1efa5d6f50725271ca85369b966e19da5b76c175b5b",
                    "294156e02fb77c860933c93da8629dbceab367629a1ff9af68ff4b03c8596b17",
                    "0483e740e929697527964c71227dd76403cdc91ca16e7a4a9a430f734481f129",
                ],
                [
                    'got the image',
                    'got the image|image number 2',
                    'got the image|image number 3',
                ],
            ),
            (
                "blahblah",
                "blahblah",
                {
                    "objectid": {
                        "tag": "got the image",
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                    },
                    "children": [
                        {
                            "objectid": {
                                "tag": "image number 2",
                                "guid": "{12345678-1234-5678-1234-567812345679}",
                            },
                            "children": [],
                        },
                        {
                            "objectid": {
                                "tag": "image number 3",
                                "guid": "{12345678-1234-5678-1234-567812345670}",
                            },
                            "children": [],
                        },
                    ],
                },
                {
                    "objectid": {
                        "tag": "got the image",
                        "treeid": "66ca3e01980a462ae88cf5e329ca479519f75d87192e93a8573e661bedb0cb9c",
                        "processtree": "blahblah|got the image",
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                    },
                    "children": [
                        {
                            "objectid": {
                                "tag": "image number 2",
                                "treeid": "9dc17d47ccef093c965c150401b717ba27728dd2c6360322526bd4c19493b154",
                                "processtree": "blahblah|got the image|image number 2",
                                "guid": "{12345678-1234-5678-1234-567812345679}",
                            },
                            "children": [],
                        },
                        {
                            "objectid": {
                                "tag": "image number 3",
                                "treeid": "020951694e1d88b34a8a3409d1f6f027173302728800e000af9d874ff9a3004d",
                                "processtree": "blahblah|got the image|image number 3",
                                "guid": "{12345678-1234-5678-1234-567812345670}",
                            },
                            "children": [],
                        },
                    ],
                },
                [
                    "66ca3e01980a462ae88cf5e329ca479519f75d87192e93a8573e661bedb0cb9c",
                    "9dc17d47ccef093c965c150401b717ba27728dd2c6360322526bd4c19493b154",
                    "020951694e1d88b34a8a3409d1f6f027173302728800e000af9d874ff9a3004d",
                ],
                [
                    'blahblah|got the image',
                    'blahblah|got the image|image number 2',
                    'blahblah|got the image|image number 3',
                ],
            ),
        ],
    )
    def test_create_hashed_node(
        parent_treeid,
        parent_processtree,
        node,
        expected_node,
        expected_treeids,
        expected_processtrees,
    ):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        p = default_so.create_process(
            guid="{12345678-1234-5678-1234-567812345678}", pid=1
        )
        p1 = default_so.create_process(
            guid="{12345678-1234-5678-1234-567812345679}", pid=2
        )
        p2 = default_so.create_process(
            guid="{12345678-1234-5678-1234-567812345670}", pid=3
        )
        default_so.add_process(p)
        default_so.add_process(p1)
        default_so.add_process(p2)

        default_so._create_hashed_node(parent_treeid, parent_processtree, node)
        assert node == expected_node
        assert [
            proc.objectid.treeid for proc in default_so.get_processes()
        ] == expected_treeids
        assert [
            proc.objectid.processtree for proc in default_so.get_processes()
        ] == expected_processtrees

    @staticmethod
    @pytest.mark.parametrize(
        "process_tree, expected_process_tree",
        [
            (
                [
                    {
                        "objectid": {
                            "tag": "?pf86\\microsoft office\\office14\\excel.exe"
                        },
                        "children": [
                            {
                                "objectid": {"tag": "?sys32\\wbem\\wmic1.exe"},
                                "children": [
                                    {
                                        "objectid": {"tag": "?sys32\\wbem\\wmic11.exe"},
                                        "children": [
                                            {
                                                "objectid": {
                                                    "tag": "?sys32\\wbem\\wmic111.exe"
                                                },
                                                "children": [],
                                            }
                                        ],
                                    },
                                    {
                                        "objectid": {"tag": "?sys32\\wbem\\wmic12.exe"},
                                        "children": [],
                                    },
                                ],
                            },
                            {
                                "objectid": {"tag": "?sys32\\wbem\\wmic2.exe"},
                                "children": [],
                            },
                            {
                                "objectid": {"tag": "?sys32\\wbem\\wmic3.exe"},
                                "children": [
                                    {
                                        "objectid": {"tag": "?sys32\\wbem\\wmic31.exe"},
                                        "children": [],
                                    },
                                    {
                                        "objectid": {"tag": "?sys32\\wbem\\wmic32.exe"},
                                        "children": [],
                                    },
                                    {
                                        "objectid": {"tag": "?sys32\\wbem\\wmic33.exe"},
                                        "children": [],
                                    },
                                ],
                            },
                        ],
                    }
                ],
                [
                    {
                        "objectid": {
                            "tag": "?pf86\\microsoft office\\office14\\excel.exe",
                            "treeid": "e0e3b025c75e49d9306866f83a77c0356d825e25b1f4fc6ddbaf6339d3a22c62",
                            "processtree": "?pf86\\microsoft office\\office14\\excel.exe",
                        },
                        "children": [
                            {
                                "objectid": {
                                    "tag": "?sys32\\wbem\\wmic1.exe",
                                    "treeid": "444ba8aca3c500c14d6b9948e6564864ffe3533b17c8a7970b20ff4145884448",
                                    "processtree": "?pf86\\microsoft office\\office14\\excel.exe|?sys32\\wbem\\wmic1.exe",
                                },
                                "children": [
                                    {
                                        "objectid": {
                                            "tag": "?sys32\\wbem\\wmic11.exe",
                                            "treeid": "29ee5e07066a9f5c9f66856c8cadaf706439b1eaef79ddad74f3cac929b54464",
                                            "processtree": "?pf86\\microsoft office\\office14\\excel.exe|?sys32\\wbem\\wmic1.exe|?sys32\\wbem\\wmic11.exe",
                                        },
                                        "children": [
                                            {
                                                "objectid": {
                                                    "tag": "?sys32\\wbem\\wmic111.exe",
                                                    "treeid": "63f4a4e5d1d649916ae2088bb28c3356b2348184c4dd332907e5498232da71ac",
                                                    "processtree": "?pf86\\microsoft office\\office14\\excel.exe|?sys32\\wbem\\wmic1.exe|?sys32\\wbem\\wmic11.exe|?sys32\\wbem\\wmic111.exe",
                                                },
                                                "children": [],
                                            }
                                        ],
                                    },
                                    {
                                        "objectid": {
                                            "tag": "?sys32\\wbem\\wmic12.exe",
                                            "treeid": "6943c25c391d6dd1f87670f5135c621d3b30b05e211074225a92da65591ef38d",
                                            "processtree": "?pf86\\microsoft office\\office14\\excel.exe|?sys32\\wbem\\wmic1.exe|?sys32\\wbem\\wmic12.exe",
                                        },
                                        "children": [],
                                    },
                                ],
                            },
                            {
                                "objectid": {
                                    "tag": "?sys32\\wbem\\wmic2.exe",
                                    "treeid": "a919e092d0d0149ce706c801290feabe3dc392d41283c9b575e6d1f0026bad1b",
                                    "processtree": "?pf86\\microsoft office\\office14\\excel.exe|?sys32\\wbem\\wmic2.exe",
                                },
                                "children": [],
                            },
                            {
                                "objectid": {
                                    "tag": "?sys32\\wbem\\wmic3.exe",
                                    "treeid": "878e93a9cb19e3d8d659dbb3bd4945e53055f3b22c79ac49fac3070b3cc1acd7",
                                    "processtree": "?pf86\\microsoft office\\office14\\excel.exe|?sys32\\wbem\\wmic3.exe",
                                },
                                "children": [
                                    {
                                        "objectid": {
                                            "tag": "?sys32\\wbem\\wmic31.exe",
                                            "treeid": "6efb85adcc57520a6b6b72afaba81d82c5deae025761f98aa33125cb37274b40",
                                            "processtree": "?pf86\\microsoft office\\office14\\excel.exe|?sys32\\wbem\\wmic3.exe|?sys32\\wbem\\wmic31.exe",
                                        },
                                        "children": [],
                                    },
                                    {
                                        "objectid": {
                                            "tag": "?sys32\\wbem\\wmic32.exe",
                                            "treeid": "099dc238ab64fb47b78557f727aa3a38a7c8b74c395c7010dd3bd2a63ec7ebdd",
                                            "processtree": "?pf86\\microsoft office\\office14\\excel.exe|?sys32\\wbem\\wmic3.exe|?sys32\\wbem\\wmic32.exe",
                                        },
                                        "children": [],
                                    },
                                    {
                                        "objectid": {
                                            "tag": "?sys32\\wbem\\wmic33.exe",
                                            "treeid": "4e99297d75424090c9b9c02fd62d19835e9ae15d3aa137ae3eab1b3c83088fa5",
                                            "processtree": "?pf86\\microsoft office\\office14\\excel.exe|?sys32\\wbem\\wmic3.exe|?sys32\\wbem\\wmic33.exe",
                                        },
                                        "children": [],
                                    },
                                ],
                            },
                        ],
                    }
                ],
            ),
        ],
    )
    def test_create_treeids(process_tree, expected_process_tree):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        default_so = SandboxOntology()
        default_so._create_treeids(process_tree)
        assert process_tree == expected_process_tree

    @staticmethod
    @pytest.mark.parametrize(
        "node, safe_treeids, expected_node",
        [
            (
                {"image": "a", "objectid": {"treeid": "a"}, "children": []},
                [],
                {"image": "a", "objectid": {"treeid": "a"}, "children": []},
            ),
            (
                {"image": "a", "objectid": {"treeid": "a"}, "children": []},
                ["a"],
                {"image": "a", "objectid": {"treeid": "a"}, "children": []},
            ),
            (
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {"image": "b", "objectid": {"treeid": "b"}, "children": []}
                    ],
                },
                [],
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {"image": "b", "objectid": {"treeid": "b"}, "children": []}
                    ],
                },
            ),
            (
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {"image": "b", "objectid": {"treeid": "b"}, "children": []}
                    ],
                },
                ["b"],
                {"children": [], "image": "a", "objectid": {"treeid": "b"}},
            ),
            (
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {"image": "b", "objectid": {"treeid": "b"}, "children": []}
                    ],
                },
                ["a"],
                {
                    "children": [
                        {"children": [], "image": "b", "objectid": {"treeid": "b"}}
                    ],
                    "image": "a",
                    "objectid": {"treeid": "a"},
                },
            ),
            (
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {"image": "b", "objectid": {"treeid": "b"}, "children": []},
                        {"image": "c", "objectid": {"treeid": "c"}, "children": []},
                    ],
                },
                [],
                {
                    "children": [
                        {"children": [], "image": "b", "objectid": {"treeid": "b"}},
                        {"children": [], "image": "c", "objectid": {"treeid": "c"}},
                    ],
                    "image": "a",
                    "objectid": {"treeid": "a"},
                },
            ),
            (
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {"image": "b", "objectid": {"treeid": "b"}, "children": []},
                        {"image": "c", "objectid": {"treeid": "c"}, "children": []},
                    ],
                },
                ["b"],
                {
                    "children": [
                        {"children": [], "image": "c", "objectid": {"treeid": "c"}}
                    ],
                    "image": "a",
                    "objectid": {"treeid": "a"},
                },
            ),
            (
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {"image": "b", "objectid": {"treeid": "b"}, "children": []},
                        {"image": "c", "objectid": {"treeid": "c"}, "children": []},
                    ],
                },
                ["c"],
                {
                    "children": [
                        {"children": [], "image": "b", "objectid": {"treeid": "b"}}
                    ],
                    "image": "a",
                    "objectid": {"treeid": "a"},
                },
            ),
            (
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {
                            "image": "b",
                            "objectid": {"treeid": "b"},
                            "children": [
                                {
                                    "image": "d",
                                    "objectid": {"treeid": "d"},
                                    "children": [],
                                }
                            ],
                        },
                        {"image": "c", "objectid": {"treeid": "c"}, "children": []},
                    ],
                },
                ["c"],
                {
                    "children": [
                        {
                            "children": [
                                {
                                    "image": "d",
                                    "objectid": {"treeid": "d"},
                                    "children": [],
                                }
                            ],
                            "image": "b",
                            "objectid": {"treeid": "b"},
                        }
                    ],
                    "image": "a",
                    "objectid": {"treeid": "a"},
                },
            ),
            (
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {
                            "image": "b",
                            "objectid": {"treeid": "b"},
                            "children": [
                                {
                                    "image": "d",
                                    "objectid": {"treeid": "d"},
                                    "children": [],
                                }
                            ],
                        },
                        {"image": "c", "objectid": {"treeid": "c"}, "children": []},
                    ],
                },
                ["d"],
                {
                    "children": [
                        {"children": [], "image": "c", "objectid": {"treeid": "c"}}
                    ],
                    "image": "a",
                    "objectid": {"treeid": "a"},
                },
            ),
            (
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {"image": "b", "objectid": {"treeid": "b"}, "children": []},
                        {
                            "image": "c",
                            "objectid": {"treeid": "c"},
                            "children": [
                                {
                                    "image": "d",
                                    "objectid": {"treeid": "d"},
                                    "children": [],
                                }
                            ],
                        },
                    ],
                },
                ["d"],
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {"image": "b", "objectid": {"treeid": "b"}, "children": []}
                    ],
                },
            ),
            (
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {"image": "b", "objectid": {"treeid": "b"}, "children": []},
                        {
                            "image": "c",
                            "objectid": {"treeid": "c"},
                            "children": [
                                {
                                    "image": "d",
                                    "objectid": {"treeid": "d"},
                                    "children": [],
                                }
                            ],
                        },
                    ],
                },
                ["b"],
                {
                    "image": "a",
                    "objectid": {"treeid": "a"},
                    "children": [
                        {
                            "image": "c",
                            "objectid": {"treeid": "c"},
                            "children": [
                                {
                                    "image": "d",
                                    "objectid": {"treeid": "d"},
                                    "children": [],
                                }
                            ],
                        }
                    ],
                },
            ),
        ],
    )
    def test_remove_safe_leaves_helper(node, safe_treeids, expected_node):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        _ = SandboxOntology._remove_safe_leaves_helper(node, safe_treeids)
        assert node == expected_node

    @staticmethod
    @pytest.mark.parametrize(
        "process_tree, safe_treeids, expected_process_tree",
        [
            (
                [{"image": "a", "children": [], "objectid": {"treeid": "blah"}}],
                [],
                [{"image": "a", "children": [], "objectid": {"treeid": "blah"}}],
            ),
            (
                [{"image": "a", "children": [], "objectid": {"treeid": "blah"}}],
                ["blah"],
                [],
            ),
            (
                [
                    {"image": "a", "children": [], "objectid": {"treeid": "blah"}},
                    {"image": "b", "children": [], "objectid": {"treeid": "blahblah"}},
                ],
                ["blah"],
                [{"image": "b", "children": [], "objectid": {"treeid": "blahblah"}}],
            ),
            (
                [
                    {"image": "a", "children": [], "objectid": {"treeid": "blah"}},
                    {"image": "b", "children": [], "objectid": {"treeid": "blahblah"}},
                ],
                ["blahblah"],
                [{"image": "a", "children": [], "objectid": {"treeid": "blah"}}],
            ),
            (
                [
                    {
                        "image": "a",
                        "children": [
                            {"image": "b", "children": [], "objectid": {"treeid": "b"}}
                        ],
                        "objectid": {"treeid": "a"},
                    },
                    {
                        "image": "c",
                        "children": [
                            {"image": "d", "children": [], "objectid": {"treeid": "d"}}
                        ],
                        "objectid": {"treeid": "c"},
                    },
                ],
                [],
                [
                    {
                        "image": "a",
                        "children": [
                            {"image": "b", "children": [], "objectid": {"treeid": "b"}}
                        ],
                        "objectid": {"treeid": "a"},
                    },
                    {
                        "image": "c",
                        "children": [
                            {"image": "d", "children": [], "objectid": {"treeid": "d"}}
                        ],
                        "objectid": {"treeid": "c"},
                    },
                ],
            ),
            (
                [
                    {
                        "image": "a",
                        "children": [
                            {"image": "b", "children": [], "objectid": {"treeid": "b"}}
                        ],
                        "objectid": {"treeid": "a"},
                    },
                    {
                        "image": "c",
                        "children": [
                            {"image": "d", "children": [], "objectid": {"treeid": "d"}}
                        ],
                        "objectid": {"treeid": "c"},
                    },
                ],
                ["a"],
                [
                    {
                        "image": "a",
                        "children": [
                            {"image": "b", "children": [], "objectid": {"treeid": "b"}}
                        ],
                        "objectid": {"treeid": "a"},
                    },
                    {
                        "image": "c",
                        "children": [
                            {"image": "d", "children": [], "objectid": {"treeid": "d"}}
                        ],
                        "objectid": {"treeid": "c"},
                    },
                ],
            ),
            (
                [
                    {
                        "image": "a",
                        "children": [
                            {"image": "b", "children": [], "objectid": {"treeid": "b"}}
                        ],
                        "objectid": {"treeid": "a"},
                    },
                    {
                        "image": "c",
                        "children": [
                            {"image": "d", "children": [], "objectid": {"treeid": "d"}}
                        ],
                        "objectid": {"treeid": "c"},
                    },
                ],
                ["b"],
                [
                    {
                        "image": "c",
                        "children": [
                            {"image": "d", "children": [], "objectid": {"treeid": "d"}}
                        ],
                        "objectid": {"treeid": "c"},
                    }
                ],
            ),
        ],
    )
    def test_remove_safe_leaves(process_tree, safe_treeids, expected_process_tree):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        SandboxOntology._remove_safe_leaves(process_tree, safe_treeids)
        assert process_tree == expected_process_tree

    @staticmethod
    @pytest.mark.parametrize(
        "event_tree, safe_treeids, expected_event_tree",
        [
            ([], [], []),
            (
                [
                    {
                        "image": "a",
                        "children": [],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    }
                ],
                [],
                [
                    {
                        "image": "a",
                        "children": [],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    }
                ],
            ),
            (
                [
                    {
                        "image": "a",
                        "children": [],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    }
                ],
                ["ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"],
                [],
            ),
            (
                [
                    {
                        "image": "a",
                        "children": [
                            {
                                "image": "b",
                                "children": [],
                                "objectid": {
                                    "treeid": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    }
                ],
                [],
                [
                    {
                        "image": "a",
                        "children": [
                            {
                                "image": "b",
                                "children": [],
                                "objectid": {
                                    "treeid": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    }
                ],
            ),
            (
                [
                    {
                        "image": "a",
                        "children": [
                            {
                                "image": "b",
                                "children": [],
                                "objectid": {
                                    "treeid": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    }
                ],
                ["d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"],
                [],
            ),
            (
                [
                    {
                        "image": "a",
                        "children": [
                            {
                                "image": "b",
                                "children": [],
                                "objectid": {
                                    "treeid": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    }
                ],
                ["ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"],
                [
                    {
                        "image": "a",
                        "children": [
                            {
                                "image": "b",
                                "children": [],
                                "objectid": {
                                    "treeid": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    }
                ],
            ),
            (
                [
                    {
                        "image": "a",
                        "children": [
                            {
                                "image": "b",
                                "children": [],
                                "objectid": {
                                    "treeid": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    },
                    {
                        "image": "c",
                        "children": [
                            {
                                "image": "d",
                                "children": [],
                                "objectid": {
                                    "treeid": "c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"
                        },
                    },
                ],
                ["d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"],
                [
                    {
                        "children": [
                            {
                                "children": [],
                                "image": "d",
                                "objectid": {
                                    "treeid": "c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04"
                                },
                            }
                        ],
                        "image": "c",
                        "objectid": {
                            "treeid": "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"
                        },
                    }
                ],
            ),
            (
                [
                    {
                        "image": "a",
                        "children": [
                            {
                                "image": "b",
                                "children": [],
                                "objectid": {
                                    "treeid": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    },
                    {
                        "image": "c",
                        "children": [
                            {
                                "image": "d",
                                "children": [],
                                "objectid": {
                                    "treeid": "c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"
                        },
                    },
                ],
                ["2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"],
                [
                    {
                        "image": "a",
                        "children": [
                            {
                                "image": "b",
                                "children": [],
                                "objectid": {
                                    "treeid": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    },
                    {
                        "image": "c",
                        "children": [
                            {
                                "image": "d",
                                "children": [],
                                "objectid": {
                                    "treeid": "c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"
                        },
                    },
                ],
            ),
            (
                [
                    {
                        "image": "a",
                        "children": [
                            {
                                "image": "b",
                                "children": [],
                                "objectid": {
                                    "treeid": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    },
                    {
                        "image": "c",
                        "children": [
                            {
                                "image": "d",
                                "children": [],
                                "objectid": {
                                    "treeid": "c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"
                        },
                    },
                ],
                ["c986d8a25b16022d5da642e622d15252820421dade338015cb8a7efe558d6d04"],
                [
                    {
                        "image": "a",
                        "children": [
                            {
                                "image": "b",
                                "children": [],
                                "objectid": {
                                    "treeid": "d107b7d075043599f95950cf82591afa47c4dce9b4d343dc6fbecb1b051ee3ef"
                                },
                            }
                        ],
                        "objectid": {
                            "treeid": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                        },
                    }
                ],
            ),
        ],
    )
    def test_filter_event_tree_against_safe_treeids(
        event_tree, safe_treeids, expected_event_tree
    ):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        filtered_event_tree = SandboxOntology._filter_event_tree_against_safe_treeids(
            event_tree, safe_treeids
        )
        assert filtered_event_tree == expected_event_tree

    @staticmethod
    @pytest.mark.parametrize(
        "artifact_list",
        [
            None,
            [],
            [
                {
                    "name": "blah",
                    "path": "blah",
                    "description": "blah",
                    "to_be_extracted": True,
                }
            ],
        ],
    )
    def test_validate_artifacts(artifact_list):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
            Artifact,
        )

        actual_validated_artifact_list = SandboxOntology._validate_artifacts(
            artifact_list
        )
        if artifact_list is None:
            artifact_list = []
        for index, artifact in enumerate(artifact_list):
            expected_artifact = Artifact(
                name=artifact["name"],
                path=artifact["path"],
                description=artifact["description"],
                to_be_extracted=artifact["to_be_extracted"],
            )
            assert expected_artifact.as_primitives(), actual_validated_artifact_list[
                index
            ].as_primitives()

    @staticmethod
    @pytest.mark.parametrize(
        "artifact, expected_result_section_title",
        [
            (None, None),
            (
                {
                    "path": "blah",
                    "name": "blah",
                    "description": "blah",
                    "to_be_extracted": True,
                },
                None,
            ),
            (
                {
                    "path": "blah",
                    "name": "123_hollowshunter/hh_process_123_blah.exe",
                    "description": "blah",
                    "to_be_extracted": True,
                },
                "HollowsHunter Injected Portable Executable",
            ),
            (
                {
                    "path": "blah",
                    "name": "123_hollowshunter/hh_process_123_blah.shc",
                    "description": "blah",
                    "to_be_extracted": True,
                },
                None,
            ),
            (
                {
                    "path": "blah",
                    "name": "123_hollowshunter/hh_process_123_blah.dll",
                    "description": "blah",
                    "to_be_extracted": True,
                },
                "HollowsHunter Injected Portable Executable",
            ),
        ],
    )
    def test_handle_artifact(artifact, expected_result_section_title):
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
            Artifact,
            HOLLOWSHUNTER_TITLE,
        )
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
            expected_result_section.add_tag(
                "dynamic.process.file_name", artifact["name"]
            )
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
            to_be_extracted=artifact["to_be_extracted"],
        )
        SandboxOntology._handle_artifact(a, parent_result_section)
        if len(parent_result_section.subsections) > 0:
            actual_result_section = parent_result_section.subsections[0]
        else:
            actual_result_section = None

        if expected_result_section is None and actual_result_section is None:
            assert True
        else:
            assert check_section_equality(
                actual_result_section, expected_result_section
            )

            additional_artifact = Artifact(
                name="321_hollowshunter/hh_process_321_blah.dll",
                path="blah",
                description="blah",
                to_be_extracted=False,
            )
            SandboxOntology._handle_artifact(additional_artifact, parent_result_section)
            expected_result_section.add_line(f"\t- {additional_artifact.name}")
            expected_result_section.add_tag(
                "dynamic.process.file_name", additional_artifact.name
            )
            expected_result_section.heuristic.add_signature_id("hollowshunter_dll")

            assert check_section_equality(
                actual_result_section, expected_result_section
            )

    @staticmethod
    def test_set_item_times():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        so.update_analysis_metadata(start_time=1.0, end_time=2.0)
        p = so.create_process(pid=1)
        so._set_item_times(p)
        assert p.start_time == 1.0
        assert p.end_time == 2.0
        assert p.objectid.time_observed == 1.0

    @staticmethod
    def test_remove_safelisted_processes():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        p = so.create_process(treeid="blah")
        so.add_process(p)
        nc = so.create_network_connection(process=p)
        so.add_network_connection(nc)
        nh = so.create_network_http(connection_details=nc)
        so.add_network_http(nh)
        nd = so.create_network_dns(connection_details=nc)
        so.add_network_dns(nd)
        sig = so.create_signature(process=p)
        so.add_signature(sig)

        so._remove_safelisted_processes(["blah"])
        assert so.get_network_http() == []
        assert so.get_network_dns() == []
        assert so.get_network_connections() == []
        assert so.get_signatures() == []
        assert so.get_processes() == []

    @staticmethod
    def test_preprocess_ontology():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            SandboxOntology,
        )

        so = SandboxOntology()
        so.update_analysis_metadata(start_time=1.0, end_time=2.0)
        p = so.create_process(pid=1)
        so.add_process(p)
        so.preprocess_ontology()
        assert p.start_time == 1.0
        assert p.end_time == 2.0
        assert p.objectid.time_observed == 1.0


@pytest.mark.parametrize(
    "blob, enforce_min, correct_tags, expected_iocs",
    [("", False, {}, [{}]),
     ("192.168.100.1", False, {'network.dynamic.ip': ['192.168.100.1']}, [{"ip": "192.168.100.1"}]),
     ("blah.ca", False, {'network.dynamic.domain': ['blah.ca']}, [{"domain": "blah.ca"}]),
     ("https://blah.ca", False,
        {'network.dynamic.domain': ['blah.ca'],
         'network.dynamic.uri': ['https://blah.ca']}, [{"domain": "blah.ca"}, {"uri": "https://blah.ca"}]),
     ("https://blah.ca/blah", False,
        {'network.dynamic.domain': ['blah.ca'],
         'network.dynamic.uri': ['https://blah.ca/blah'],
         "network.dynamic.uri_path": ["/blah"]}, [{"domain": "blah.ca"}, {"uri": "https://blah.ca/blah"}]),
     ("drive:\\\\path to\\\\microsoft office\\\\officeverion\\\\winword.exe", False, {}, [{}]),
     ("DRIVE:\\\\PATH TO\\\\MICROSOFT OFFICE\\\\OFFICEVERION\\\\"
        "WINWORD.EXE C:\\\\USERS\\\\BUDDY\\\\APPDATA\\\\LOCAL\\\\TEMP\\\\BLAH.DOC",
        False, {}, [{}]),
     ("DRIVE:\\\\PATH TO\\\\PYTHON27.EXE C:\\\\USERS\\\\BUDDY\\\\APPDATA\\\\LOCAL\\\\TEMP\\\\BLAH.py",
        False, {}, [{}]),
     ("POST /some/thing/bad.exe HTTP/1.0\nUser-Agent: Mozilla\nHost: evil.ca\nAccept: */*\n"
     "Content-Type: application/octet-stream\nContent-Encoding: binary\n\nConnection: close",
        False, {"network.dynamic.domain": ["evil.ca"]}, [{"domain": "evil.ca"}]),
     ("evil.ca/some/thing/bad.exe",
        False, {"network.dynamic.domain": ["evil.ca"],
                "network.dynamic.uri": ["ftp://evil.ca/some/thing/bad.exe"],
                "network.dynamic.uri_path": ["/some/thing/bad.exe"]}, [{"domain": "evil.ca"},
                                                                       {"uri": "ftp://evil.ca/some/thing/bad.exe"}]),
     ("POST abc.de#fgh", True, {}, [{}]), ])
def test_extract_iocs_from_text_blob(blob, enforce_min, correct_tags, expected_iocs):
    from assemblyline_v4_service.common.dynamic_service_helper import extract_iocs_from_text_blob, SandboxOntology
    from assemblyline_v4_service.common.result import ResultTableSection
    test_result_section = ResultTableSection("blah")
    so_sig = SandboxOntology.Signature()
    default_iocs = []
    extract_iocs_from_text_blob(blob, test_result_section, so_sig=so_sig, enforce_char_min=enforce_min)
    assert test_result_section.tags == correct_tags
    if correct_tags:
        for expected_ioc in expected_iocs:
            default_ioc = SandboxOntology.Signature.Subject().as_primitives()
            for key, value in expected_ioc.items():
                default_ioc[key] = value
            default_iocs.append(default_ioc)
        assert so_sig.as_primitives()["subjects"] == default_iocs
