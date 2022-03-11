import pytest
import os

SERVICE_CONFIG_NAME = "service_manifest.yml"
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)


def setup_module():
    if not os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        open_manifest = open(TEMP_SERVICE_CONFIG_PATH, "w")
        open_manifest.write(
            "name: Sample\nversion: sample\ndocker_config: \n  image: sample\nheuristics:\n  - heur_id: 17\n"
            "    name: blah\n    description: blah\n    filetype: '*'\n    score: 250")


def teardown_module():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)


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


@pytest.fixture
def dummy_object_class():
    class DummyObject:
        def __init__(self, id=None) -> None:
            self.id = id
    yield DummyObject


@pytest.fixture
def dummy_timestamp_class():
    class DummyEvent:
        def __init__(self, item):
            self.timestamp = item["timestamp"] if item.get("timestamp") else item["start_time"]
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
            self.task.supplementary.append({"path": path, "name": name, "description": description})

        def add_extracted(self, path, name, description):
            self.task.extracted.append({"path": path, "name": name, "description": description})

    yield DummyRequest


class TestModule:
    @staticmethod
    def test_update_object_items(dummy_object_class):
        from assemblyline_v4_service.common.dynamic_service_helper import update_object_items
        dummy = dummy_object_class()
        update_object_items(dummy, {"id": "blah", "something": "blah"})
        assert dummy.id == "blah"
        assert dummy.__dict__ == {"id": "blah"}
        assert update_object_items(dummy, {"id": None}) is None


class TestArtifact:
    @staticmethod
    @pytest.mark.parametrize("name, path, description, to_be_extracted",
                             [
                                 (None, None, None, None),
                                 ("blah", "blah", "blah", True),
                                 ("blah", "blah", "blah", False),
                             ]
                             )
    def test_artifact_init(name, path, description, to_be_extracted):
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

    @staticmethod
    def test_artifact_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import Artifact
        a = Artifact(name="blah", path="blah", description="blah", to_be_extracted="blah")
        assert a.as_primitives() == {
            "name": "blah",
            "path": "blah",
            "description": "blah",
            "to_be_extracted": "blah",
        }


class TestProcess:
    @staticmethod
    def test_process_init():
        from assemblyline_v4_service.common.dynamic_service_helper import Process

        default_p = Process()
        assert default_p.guid is None
        assert default_p.pguid is None
        assert default_p.pimage is None
        assert default_p.pcommand_line is None
        assert default_p.ppid is None
        assert default_p.pid is None
        assert default_p.image is None
        assert default_p.command_line is None
        assert default_p.start_time is None
        assert default_p.end_time is None
        assert default_p.tree_id is None
        assert default_p.tag is None
        assert default_p._normalize is False

        set_p = Process(
            guid="{12345678-1234-5678-1234-567812345678}",
            pguid="{12345678-1234-5678-1234-567812345678}",
            pimage="C:\\Windows\\System32\\cmd.exe",
            pcommand_line="C:\\Windows\\System32\\cmd.exe -m bad.exe",
            ppid=123,
            pid=123,
            image="C:\\Windows\\System32\\cmd.exe",
            command_line="C:\\Windows\\System32\\cmd.exe -m bad.exe",
            start_time=1.0,
            end_time=1.0,
            tree_id="blah",
            tag="blah",
            _normalize=True,
        )

        assert set_p.guid == "{12345678-1234-5678-1234-567812345678}"
        assert set_p.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert set_p.pimage == "?sys32\\cmd.exe"
        assert set_p.pcommand_line == "?sys32\cmd.exe -m bad.exe"
        assert set_p.ppid == 123
        assert set_p.pid == 123
        assert set_p.image == "?sys32\\cmd.exe"
        assert set_p.command_line == "?sys32\cmd.exe -m bad.exe"
        assert set_p.start_time == 1.0
        assert set_p.end_time == 1.0
        assert set_p.tree_id == "blah"
        assert set_p.tag == "blah"
        assert set_p._normalize is True

        with pytest.raises(ValueError):
            Process(pid="a")

        with pytest.raises(ValueError):
            Process(start_time=2.0, end_time=1.0)

    @staticmethod
    def test_process_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        p = Process()
        assert p.as_primitives() == {
            "guid": None,
            "pguid": None,
            "pimage": None,
            "pcommand_line": None,
            "ppid": None,
            "pid": None,
            "image": None,
            "command_line": None,
            "start_time": None,
            "end_time": None,
            "tree_id": None,
            "tag": None,
        }

    @staticmethod
    def test_process_assign_guid():
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        from uuid import UUID
        p = Process()
        p.assign_guid()
        assert str(UUID(p.guid))

    @staticmethod
    def test_set_parent():
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        child_p = Process()
        parent_p = Process(guid="{12345678-1234-5678-1234-567812345678}", image="blah", command_line="blah", pid=123)
        child_p.set_parent(parent_p)

        assert child_p.pguid == parent_p.guid
        assert child_p.pimage == parent_p.image
        assert child_p.pcommand_line == parent_p.command_line
        assert child_p.ppid == parent_p.pid

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
    def test_normalize():
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        p = Process(image="C:\\program files\\blah", pimage="C:\\program files\\blah",
                    command_line="C:\\program files\\blah", pcommand_line="C:\\program files\\blah")
        p.normalize()
        assert p.image == "?pf86\\blah"
        assert p.pimage == "?pf86\\blah"
        assert p.command_line == "?pf86\\blah"
        assert p.pcommand_line == "?pf86\\blah"

    @staticmethod
    def test_normalize_paths():
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        p = Process(image="C:\\program files\\blah", pimage="C:\\program files\\blah",
                    command_line="C:\\program files\\blah", pcommand_line="C:\\program files\\blah")
        p.normalize_paths(["image", "pimage", "command_line", "pcommand_line"])
        assert p.image == "?pf86\\blah"
        assert p.pimage == "?pf86\\blah"
        assert p.command_line == "?pf86\\blah"
        assert p.pcommand_line == "?pf86\\blah"

    @staticmethod
    def test_normalize_kwargs():
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        kwargs = {
            "image": "C:\\program files\\blah",
            "pimage": "C:\\program files\\blah",
            "command_line": "C:\\program files\\blah",
            "pcommand_line": "C:\\program files\\blah",
        }
        assert Process.normalize_kwargs(kwargs) == {
            "image": "?pf86\\blah",
            "pimage": "?pf86\\blah",
            "command_line": "?pf86\\blah",
            "pcommand_line": "?pf86\\blah",
        }

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
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        p = Process(image=path)
        actual_result = p._determine_arch(path)
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
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        actual_result = Process._pattern_substitution(path, rule)
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
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        actual_result = Process._regex_substitution(path, rule)
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
        from assemblyline_v4_service.common.dynamic_service_helper import Process
        actual_result = Process._normalize_path(path, arch)
        assert actual_result == expected_result


class TestNetworkConnection:
    @staticmethod
    def test_network_connection_init():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkConnection, Process
        from uuid import UUID

        default_nc = NetworkConnection()
        assert str(UUID(default_nc.guid))
        assert default_nc.process is None
        assert default_nc.source_ip is None
        assert default_nc.source_port is None
        assert default_nc.destination_ip is None
        assert default_nc.destination_port is None
        assert default_nc.transport_layer_protocol is None
        assert default_nc.direction is None
        assert default_nc.tree_id is None
        assert default_nc.tag is None
        assert default_nc._normalize is False

        with pytest.raises(ValueError):
            NetworkConnection(
                transport_layer_protocol="blah",
            )

        with pytest.raises(ValueError):
            NetworkConnection(
                direction="blah",
            )

        set_nc = NetworkConnection(
            guid="{12345678-1234-5678-1234-567812345678}",
            source_ip="blah",
            source_port=123,
            destination_ip="blah",
            destination_port=123,
            transport_layer_protocol="tcp",
            direction="outbound",
        )

        assert set_nc.guid == "{12345678-1234-5678-1234-567812345678}"
        assert set_nc.source_ip == "blah"
        assert set_nc.source_port == 123
        assert set_nc.destination_ip == "blah"
        assert set_nc.destination_port == 123
        assert set_nc.transport_layer_protocol == "tcp"
        assert set_nc.direction == "outbound"

        p = Process(image="C:\\Windows\\System32\\cmd.exe")
        nc_w_p = NetworkConnection(process=p, _normalize=True)
        assert nc_w_p.process.image == "?sys32\\cmd.exe"

    @staticmethod
    def test_network_connection_assign_guid():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkConnection
        from uuid import UUID

        nc = NetworkConnection()
        nc.assign_guid()
        assert str(UUID(nc.guid))

    @staticmethod
    def test_network_connection_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkConnection
        default_nc = NetworkConnection()
        default_nc.update_process(pid=123, invalid="blah")
        assert default_nc.process.pid == 123

        normalized_nc = NetworkConnection(_normalize=True)
        normalized_nc.update_process(image="C:\\Windows\\System32\\cmd.exe", invalid="blah")
        assert normalized_nc.process.image == "?sys32\\cmd.exe"

        normalized_nc.update_process(image=None)
        assert normalized_nc.process.image == "?sys32\\cmd.exe"

    @staticmethod
    def test_set_network_connection_process():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkConnection, Process

        default_nc = NetworkConnection()
        p1 = Process(pid=1)
        default_nc.set_process(p1)
        assert default_nc.process.pid == 1

    @staticmethod
    def test_network_connection_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkConnection
        from uuid import UUID

        default_nc = NetworkConnection()
        default_nc_as_primitives = default_nc.as_primitives()
        assert str(UUID(default_nc_as_primitives.pop("guid")))
        assert default_nc_as_primitives == {
            "process": None,
            "source_ip": None,
            "source_port": None,
            "destination_ip": None,
            "destination_port": None,
            "transport_layer_protocol": None,
            "direction": None,
            "timestamp": None,
            "tree_id": None,
            "tag": None,
        }


class TestNetworkDNS:
    @staticmethod
    def test_network_dns_init():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkDNS

        default_nd = NetworkDNS()

        assert default_nd.connection_details.process is None
        assert default_nd.connection_details.source_ip is None
        assert default_nd.connection_details.source_port is None
        assert default_nd.connection_details.destination_ip is None
        assert default_nd.connection_details.destination_port is None
        assert default_nd.connection_details.transport_layer_protocol is None
        assert default_nd.connection_details.direction is None
        assert default_nd.domain is None
        assert default_nd.resolved_ips == []

        set_nd = NetworkDNS(
            domain="blah",
            resolved_ips=["blah"],
        )

        assert set_nd.domain == "blah"
        assert set_nd.resolved_ips == ["blah"]

    @staticmethod
    def test_network_dns_update():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkDNS
        default_nd = NetworkDNS()
        default_nd.update(domain="blah", invalid="blah")
        assert default_nd.domain == "blah"

    @staticmethod
    def test_network_dns_update_connection_details():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkDNS
        default_nd = NetworkDNS()
        default_nd.update_connection_details(destination_ip="blah", invalid="blah")
        assert default_nd.connection_details.destination_ip == "blah"

    @staticmethod
    def test_network_dns_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkDNS
        default_nd = NetworkDNS()
        default_nd.update_process(pid=123, invalid="blah")
        assert default_nd.connection_details.process.pid == 123

        normalized_dns = NetworkDNS(_normalize=True)
        normalized_dns.update_process(image="C:\\Windows\\System32\\cmd.exe", invalid="blah")
        assert normalized_dns.connection_details.process.image == "?sys32\\cmd.exe"

        normalized_dns.update_process(image=None)
        assert normalized_dns.connection_details.process.image == "?sys32\\cmd.exe"

    @staticmethod
    def test_network_dns_set_network_connection():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkDNS, NetworkConnection
        default_nd = NetworkDNS(domain="blah")
        default_nc = NetworkConnection(destination_ip="1.1.1.1")
        default_nd.set_network_connection(default_nc)
        assert default_nd.connection_details.destination_ip == "1.1.1.1"

    @ staticmethod
    def test_network_dns_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkDNS
        from uuid import UUID
        default_nd = NetworkDNS()
        default_nd_as_primitives = default_nd.as_primitives()
        assert str(UUID(default_nd_as_primitives["connection_details"].pop("guid")))
        assert default_nd_as_primitives == {
            "connection_details": {
                "process": None,
                "source_ip": None,
                "source_port": None,
                "destination_ip": None,
                "destination_port": None,
                "transport_layer_protocol": None,
                "direction": None,
                "timestamp": None,
                "tree_id": None,
                "tag": None,
            },
            "domain": None,
            "resolved_ips": [],
        }


class TestNetworkHTTP:
    @staticmethod
    def test_network_http_init():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP

        default_nh = NetworkHTTP()
        assert default_nh.connection_details.process is None
        assert default_nh.connection_details.source_ip is None
        assert default_nh.connection_details.source_port is None
        assert default_nh.connection_details.destination_ip is None
        assert default_nh.connection_details.destination_port is None
        assert default_nh.connection_details.transport_layer_protocol is None
        assert default_nh.connection_details.direction is None
        assert default_nh.uri is None
        assert default_nh.request_headers == {}
        assert default_nh.request_method is None
        assert default_nh.response_status_code is None

        set_nh = NetworkHTTP(
            uri="blah",
            request_headers={"a": "b"},
            request_method="blah",
            response_status_code=123,
        )

        assert set_nh.uri == "blah"
        assert set_nh.request_headers == {"a": "b"}
        assert set_nh.request_method == "blah"
        assert set_nh.response_status_code == 123

    @staticmethod
    def test_network_http_update():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP
        default_nh = NetworkHTTP()
        default_nh.update(uri="blah", invalid="blah")
        assert default_nh.uri == "blah"

    @staticmethod
    def test_network_http_update_connection_details():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP
        default_nh = NetworkHTTP()
        default_nh.update_connection_details(destination_ip="blah", invalid="blah")
        assert default_nh.connection_details.destination_ip == "blah"

    @staticmethod
    def test_network_http_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP
        default_nh = NetworkHTTP()
        default_nh.update_process(pid=123, invalid="blah")
        assert default_nh.connection_details.process.pid == 123

        normalized_http = NetworkHTTP(_normalize=True)
        normalized_http.update_process(image="C:\\Windows\\System32\\cmd.exe", invalid="blah")
        assert normalized_http.connection_details.process.image == "?sys32\\cmd.exe"

        normalized_http.update_process(image=None)
        assert normalized_http.connection_details.process.image == "?sys32\\cmd.exe"

    @staticmethod
    def test_network_http_set_network_connection():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP, NetworkConnection
        default_nh = NetworkHTTP(uri="blah")
        default_nc = NetworkConnection(destination_ip="1.1.1.1")
        default_nh.set_network_connection(default_nc)
        assert default_nh.connection_details.destination_ip == "1.1.1.1"

    @ staticmethod
    def test_network_http_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import NetworkHTTP
        from uuid import UUID

        default_nh = NetworkHTTP()
        default_nh_as_primitives = default_nh.as_primitives()
        assert str(UUID(default_nh_as_primitives["connection_details"].pop("guid")))
        assert default_nh_as_primitives == {
            "connection_details": {
                "process": None,
                "source_ip": None,
                "source_port": None,
                "destination_ip": None,
                "destination_port": None,
                "transport_layer_protocol": None,
                "direction": None,
                "timestamp": None,
                "tree_id": None,
                "tag": None,
            },
            "uri": None,
            "request_headers": {},
            "request_method": None,
            "response_status_code": None,
        }


class TestMachineMetadata:
    @staticmethod
    def test_machine_metadata_init():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

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
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

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
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_mm = SandboxOntology.AnalysisMetadata.MachineMetadata()
        default_mm.load_from_json({
            "ip": "blah",
            "hypervisor": "blah",
            "hostname": "blah",
            "platform": "blah",
            "version": "blah",
            "architecture": "blah",
        })
        assert default_mm.ip == "blah"
        assert default_mm.hypervisor == "blah"
        assert default_mm.hostname == "blah"
        assert default_mm.platform == "blah"
        assert default_mm.version == "blah"
        assert default_mm.architecture == "blah"


class TestAnalysisMetadata:
    @staticmethod
    def test_analysis_metadata_init():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

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
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

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
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_am = SandboxOntology.AnalysisMetadata()
        default_am.load_from_json({
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
        })
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


class TestIOC:
    @staticmethod
    def test_ioc_init():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Process

        default_ioc = SandboxOntology.Signature.IOC()
        assert default_ioc.ip is None
        assert default_ioc.domain is None
        assert default_ioc.uri is None
        assert default_ioc.uri_path is None
        assert default_ioc.process is None
        assert default_ioc._normalize is False

        set_ioc = SandboxOntology.Signature.IOC(
            ip="blah",
            domain="blah",
            uri="blah",
            uri_path="blah",
        )
        assert set_ioc.ip == "blah"
        assert set_ioc.domain == "blah"
        assert set_ioc.uri == "blah"
        assert set_ioc.uri_path == "blah"

        p = Process(image="C:\\Windows\\System32\\cmd.exe")
        ioc_w_p = SandboxOntology.Signature.IOC(process=p, _normalize=True)
        assert ioc_w_p.process.image == "?sys32\\cmd.exe"

    @staticmethod
    def test_ioc_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_ioc = SandboxOntology.Signature.IOC()
        default_ioc.update_process(guid="blah")
        assert default_ioc.process.guid == "blah"

        normalized_ioc = SandboxOntology.Signature.IOC(_normalize=True)
        normalized_ioc.update_process(image="C:\\Windows\\System32\\cmd.exe")
        assert normalized_ioc.process.image == "?sys32\\cmd.exe"

    @staticmethod
    def test_ioc_set_process():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Process

        default_ioc = SandboxOntology.Signature.IOC()
        p1 = Process(pid=1)
        default_ioc.set_process(p1)
        assert default_ioc.process.pid == 1

    @staticmethod
    def test_ioc_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_ioc = SandboxOntology.Signature.IOC()
        assert default_ioc.as_primitives() == {
            "ip": None,
            "domain": None,
            "uri": None,
            "uri_path": None,
            "process": None,
        }


class TestSignature:
    @staticmethod
    def test_signature_init():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Process

        default_sig = SandboxOntology.Signature()
        assert default_sig.process is None
        assert default_sig.name is None
        assert default_sig.description is None
        assert default_sig.attack == []
        assert default_sig.iocs == []
        assert default_sig._normalize is False

        set_sig = SandboxOntology.Signature(
            name="blah",
            description="blah",
        )
        assert set_sig.name == "blah"
        assert set_sig.description == "blah"

        p = Process(image="C:\\Windows\\System32\\cmd.exe")
        sig_w_p = SandboxOntology.Signature.IOC(process=p, _normalize=True)
        assert sig_w_p.process.image == "?sys32\\cmd.exe"

    @staticmethod
    def test_signature_update():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_sig = SandboxOntology.Signature()
        default_sig.update(description="blah")
        assert default_sig.description == "blah"

    @staticmethod
    def test_signature_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_sig = SandboxOntology.Signature()
        default_sig.update_process(guid="blah")
        assert default_sig.process.guid == "blah"

        normalized_sig = SandboxOntology.Signature(_normalize=True)
        normalized_sig.update_process(image="C:\\Windows\\System32\\cmd.exe")
        assert normalized_sig.process.image == "?sys32\\cmd.exe"

        normalized_sig.update_process(image=None)
        assert normalized_sig.process.image == "?sys32\\cmd.exe"

    @staticmethod
    def test_signature_set_process():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Process

        default_sig = SandboxOntology.Signature()
        p1 = Process(pid=1)
        default_sig.set_process(p1)
        assert default_sig.process.pid == 1

    @staticmethod
    def test_add_attack_id():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_sig = SandboxOntology.Signature()
        default_sig.add_attack_id("T1187")
        assert default_sig.attack == [{'attack_id': 'T1187', 'categories': [
            'credential-access'], 'pattern': 'Forced Authentication'}]

    @staticmethod
    def test_add_ioc():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_sig = SandboxOntology.Signature()
        default_sig.add_ioc(domain="blah")
        assert default_sig.iocs[0].domain == "blah"

    @staticmethod
    def test_add_process_ioc():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_sig = SandboxOntology.Signature()
        default_sig.add_process_ioc(guid="blah")
        assert default_sig.iocs[0].process.guid == "blah"

    @staticmethod
    def test_signature_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_ioc = SandboxOntology.Signature()
        assert default_ioc.as_primitives() == {
            "name": None,
            "description": None,
            "attack": [],
            "iocs": [],
            "process": None,
        }


class TestSandboxOntology:
    @staticmethod
    def test_sandbox_ontology_init():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

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
        assert default_so._normalize_paths is False

        set_so = SandboxOntology(sandbox_name="blah", sandbox_version="blah", normalize_paths=True)
        assert set_so.sandbox_name == "blah"
        assert set_so.sandbox_version == "blah"
        assert set_so._normalize_paths is True

    @staticmethod
    def test_update_analysis_metadata():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        default_so.update_analysis_metadata(task_id=123, invalid="blah")
        assert default_so.analysis_metadata.task_id == 123

    @staticmethod
    def test_update_machine_metadata():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        default_so.update_machine_metadata(ip="blah", invalid="blah")
        assert default_so.analysis_metadata.machine_metadata.ip == "blah"

    @staticmethod
    def test_sandbox_ontology_create_process():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        p = default_so.create_process(guid="{12345678-1234-5678-1234-567812345678}")
        assert p.guid == "{12345678-1234-5678-1234-567812345678}"

        normalized_so = SandboxOntology(normalize_paths=True)
        p = normalized_so.create_process(image="C:\\Windows\\System32\\cmd.exe")
        assert p.image == "?sys32\\cmd.exe"

    @staticmethod
    def test_add_process():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        assert default_so.processes == []

        p = default_so.create_process(guid="{12345678-1234-5678-1234-567812345678}")
        default_so.add_process(p)
        assert default_so.processes[0].as_primitives() == {
            "guid": "{12345678-1234-5678-1234-567812345678}",
            "pguid": None,
            "pimage": None,
            "pcommand_line": None,
            "ppid": None,
            "pid": None,
            "image": None,
            "command_line": None,
            "start_time": float("-inf"),
            "end_time": float("inf"),
            "tree_id": None,
            "tag": None,
        }

    @staticmethod
    def test_sandbox_ontology_update_process():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

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

        normalized_so = SandboxOntology(normalize_paths=True)
        p = normalized_so.create_process(guid="{12345678-1234-5678-1234-567812345678}",
                                         image="C:\\Windows\\System32\\cmd.exe",
                                         pid=1, start_time=1.0)
        normalized_so.add_process(p)
        normalized_so.update_process(guid="{12345678-1234-5678-1234-567812345678}",
                                     pimage="C:\\Windows\\System32\\cmd.exe")
        assert normalized_so.processes[0].image == "?sys32\\cmd.exe"
        assert normalized_so.processes[0].pimage == "?sys32\\cmd.exe"

        normalized_so.update_process(pid=1, start_time=1.0, command_line="C:\\Windows\\System32\\cmd.exe")
        assert normalized_so.processes[0].command_line == "?sys32\\cmd.exe"

    @staticmethod
    def test_set_parent_details():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Process

        so = SandboxOntology()
        parent_process = Process(guid="{12345678-1234-5678-1234-567812345678}",
                                 image="blah.exe", start_time=2.0, end_time=3.0, pid=1)
        so.add_process(parent_process)
        p1 = Process(pguid="{12345678-1234-5678-1234-567812345678}")
        so.set_parent_details(p1)
        assert p1.as_primitives() == {
            "guid": None,
            "pguid": "{12345678-1234-5678-1234-567812345678}",
            "pimage": "blah.exe",
            "pcommand_line": None,
            "ppid": 1,
            "pid": None,
            "image": None,
            "command_line": None,
            "start_time": None,
            "end_time": None,
            "tree_id": None,
            "tag": None,
        }

        p2 = Process(ppid=1, start_time=3.0)
        so.set_parent_details(p2)
        assert p2.as_primitives() == {
            "guid": None,
            "pguid": "{12345678-1234-5678-1234-567812345678}",
            "pimage": "blah.exe",
            "pcommand_line": None,
            "ppid": 1,
            "pid": None,
            "image": None,
            "command_line": None,
            "start_time": 3.0,
            "end_time": None,
            "tree_id": None,
            "tag": None,
        }

    @staticmethod
    def test_set_child_details():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Process

        so = SandboxOntology()
        child_process1 = Process(guid="{12345678-1234-5678-1234-567812345678}", image="blah.exe",
                                 start_time=2.0, end_time=3.0, pid=1, pguid="{12345678-1234-5678-1234-567812345679}")
        so.add_process(child_process1)
        child_process2 = Process(guid="{12345678-1234-5678-1234-567812345670}", image="blah.exe",
                                 start_time=2.0, end_time=3.0, pid=3, ppid=2)
        so.add_process(child_process2)
        parent = Process(guid="{12345678-1234-5678-1234-567812345679}", pid=2, start_time=2.0, image="parent.exe")
        so.set_child_details(parent)
        assert child_process1.as_primitives() == {
            "guid": "{12345678-1234-5678-1234-567812345678}",
            "pguid": "{12345678-1234-5678-1234-567812345679}",
            "pimage": "parent.exe",
            "pcommand_line": None,
            "ppid": 2,
            "pid": 1,
            "image": "blah.exe",
            "command_line": None,
            "start_time": 2.0,
            "end_time": 3.0,
            "tree_id": None,
            "tag": None,
        }
        assert child_process2.as_primitives() == {
            "guid": "{12345678-1234-5678-1234-567812345670}",
            "pguid": "{12345678-1234-5678-1234-567812345679}",
            "pimage": "parent.exe",
            "pcommand_line": None,
            "ppid": 2,
            "pid": 3,
            "image": "blah.exe",
            "command_line": None,
            "start_time": 2.0,
            "end_time": 3.0,
            "tree_id": None,
            "tag": None,
        }

    @staticmethod
    @pytest.mark.parametrize("events, validated_events_num",
                             [([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "timestamp": 1.0,
                                 "guid": "{12345678-1234-5678-1234-567812345678}",
                                 "pguid": "{12345678-1234-5678-1234-567812345679}"}],
                               1), ])
    def test_get_processes(events, validated_events_num):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        so = SandboxOntology()
        for event in events:
            p = so.create_process(**event)
            so.add_process(p)
        assert len(so.get_processes()) == validated_events_num

    @staticmethod
    def test_get_guid_by_pid_and_time():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        so = SandboxOntology()
        assert so.get_guid_by_pid_and_time(1, 0.0) is None

        p = so.create_process(pid=1, start_time=0.0, end_time=1.0,
                              guid="{12345678-1234-5678-1234-567812345678}")
        so.add_process(p)
        assert so.get_guid_by_pid_and_time(1, 0.5) == "{12345678-1234-5678-1234-567812345678}"

    @staticmethod
    def test_get_processes_by_ppid_and_time():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        so = SandboxOntology()
        assert so.get_processes_by_ppid_and_time(1, 0.0) == []

        p = so.create_process(pid=1, start_time=0.0, end_time=1.0,
                              guid="{12345678-1234-5678-1234-567812345678}", ppid=2)
        so.add_process(p)
        assert so.get_processes_by_ppid_and_time(2, 0.5) == [p]

    @staticmethod
    def test_get_pguid_by_pid_and_time():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        so = SandboxOntology()
        assert so.get_pguid_by_pid_and_time(1, 0.0) is None

        child = so.create_process(pid=1, start_time=0.0, end_time=1.0, pguid="{12345678-1234-5678-1234-567812345678}")
        so.add_process(child)
        assert so.get_pguid_by_pid_and_time(1, 0.5) == "{12345678-1234-5678-1234-567812345678}"

    @staticmethod
    def test_is_guid_in_gpm():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        so = SandboxOntology()
        guid = "{12345678-1234-5678-1234-567812345678}"
        assert not so.is_guid_in_gpm(guid)

        p = so.create_process(pid=1, start_time=0.0, end_time=1.0,
                              guid=guid)
        so.add_process(p)
        assert so.is_guid_in_gpm(guid)

    @staticmethod
    def test_get_process_by_guid():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        so = SandboxOntology()
        assert not so.get_process_by_guid(None)

        guid = "{12345678-1234-5678-1234-567812345678}"
        assert not so.get_process_by_guid(guid)

        p = so.create_process(guid=guid)
        so.add_process(p)
        assert so.get_process_by_guid(guid) == p

    @staticmethod
    def test_get_process_by_pid_and_time():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        so = SandboxOntology()
        assert so.get_process_by_pid_and_time(None, 1.0) is None
        assert so.get_process_by_pid_and_time(1, None) is None
        assert so.get_process_by_pid_and_time(1, 1.0) is None

        p = so.create_process(pid=1, start_time=1.0, end_time=2.0)
        so.add_process(p)
        assert so.get_process_by_pid_and_time(1, 1.5) == p

    @staticmethod
    def test_get_processes_by_pguid():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        so = SandboxOntology()
        assert not so.get_processes_by_pguid(None)

        guid = "{12345678-1234-5678-1234-567812345678}"
        assert not so.get_processes_by_pguid(guid)

        p = so.create_process(pguid=guid)
        so.add_process(p)
        assert so.get_processes_by_pguid(guid) == [p]

    @staticmethod
    def test_create_network_connection():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nc = default_so.create_network_connection(guid="blah")
        assert nc.guid == "blah"

        normalized_so = SandboxOntology(normalize_paths=True)
        nc = normalized_so.create_network_connection()
        assert nc._normalize is True

    @staticmethod
    def test_add_network_connection():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from uuid import UUID

        default_so = SandboxOntology()
        assert default_so.network_connections == []

        nc = default_so.create_network_connection()
        default_so.add_network_connection(nc)
        nc_as_primitives = default_so.network_connections[0].as_primitives()
        assert str(UUID(nc_as_primitives.pop("guid")))
        assert nc_as_primitives == {
            "process": None,
            "source_ip": None,
            "source_port": None,
            "destination_ip": None,
            "destination_port": None,
            "transport_layer_protocol": None,
            "direction": None,
            "timestamp": None,
            "tree_id": None,
            "tag": None,
        }

    @staticmethod
    def test_get_network_connections():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nc = default_so.create_network_connection()
        default_so.add_network_connection(nc)
        assert default_so.get_network_connections() == [nc]

    @staticmethod
    def test_get_network_connection_by_pid():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nc = default_so.create_network_connection(destination_ip="1.1.1.1")
        nc.update_process(pid=1)
        default_so.add_network_connection(nc)
        assert default_so.get_network_connection_by_pid(1) == []

        p = default_so.create_process(pid=2, start_time=1.0, end_time=5.0)
        default_so.add_process(p)
        nc2 = default_so.create_network_connection(destination_ip="1.1.1.1", timestamp=2.0)
        nc2.update_process(pid=2, start_time=2.0)
        default_so.add_network_connection(nc2)
        assert default_so.get_network_connection_by_pid(2)[0].destination_ip == "1.1.1.1"

    @staticmethod
    def test_get_network_connection_by_details():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nc = default_so.create_network_connection(
            destination_ip="1.1.1.1", destination_port=1, source_ip="2.2.2.2", source_port=2, timestamp=1.5)
        default_so.add_network_connection(nc)
        assert default_so.get_network_connection_by_details(
            source_ip="2.2.2.2", source_port=2, destination_ip="1.1.1.1", destination_port=1, timestamp=2) == nc

    @staticmethod
    def test_create_network_dns():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nd = default_so.create_network_dns(domain="blah")
        assert nd.domain == "blah"

        normalized_so = SandboxOntology(normalize_paths=True)
        nd = normalized_so.create_network_dns()
        assert nd.connection_details._normalize is True

    @staticmethod
    def test_add_network_dns():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from uuid import UUID

        default_so = SandboxOntology()
        assert default_so.network_dns == []

        nd = default_so.create_network_dns()
        default_so.add_network_dns(nd)
        nd_as_primitives = default_so.network_dns[0].as_primitives()
        assert str(UUID(nd_as_primitives["connection_details"].pop("guid")))
        assert nd_as_primitives == {
            "connection_details": {
                "process": None,
                "source_ip": None,
                "source_port": None,
                "destination_ip": None,
                "destination_port": None,
                "transport_layer_protocol": None,
                "direction": None,
                "timestamp": None,
                "tree_id": None,
                "tag": None,
            },
            "domain": None,
            "resolved_ips": [],
        }

    @staticmethod
    def test_get_network_dns():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nd = default_so.create_network_dns()
        default_so.add_network_dns(nd)
        assert default_so.get_network_dns() == [nd]

    @staticmethod
    def test_get_domain_by_destination_ip():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        assert default_so.get_domain_by_destination_ip("1.1.1.1") is None

        nd1 = default_so.create_network_dns(domain="blah.com", resolved_ips=["1.1.1.1"])
        default_so.add_network_dns(nd1)
        assert default_so.get_domain_by_destination_ip("1.1.1.1") == "blah.com"

        nd2 = default_so.create_network_dns(domain="blah.ca", resolved_ips=["1.1.1.1"])
        default_so.add_network_dns(nd2)
        assert default_so.get_domain_by_destination_ip("1.1.1.1") == "blah.com"

    @staticmethod
    def test_create_network_http():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nh = default_so.create_network_http(uri="blah")
        assert nh.uri == "blah"

        normalized_so = SandboxOntology(normalize_paths=True)
        nh = normalized_so.create_network_http()
        assert nh.connection_details._normalize is True

    @staticmethod
    def test_add_network_http():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from uuid import UUID

        default_so = SandboxOntology()
        assert default_so.network_http == []

        nh = default_so.create_network_http()
        default_so.add_network_http(nh)
        nh_as_primitives = default_so.network_http[0].as_primitives()
        assert str(UUID(nh_as_primitives["connection_details"].pop("guid")))
        assert nh_as_primitives == {
            "connection_details": {
                "process": None,
                "source_ip": None,
                "source_port": None,
                "destination_ip": None,
                "destination_port": None,
                "transport_layer_protocol": None,
                "direction": None,
                "timestamp": None,
                "tree_id": None,
                "tag": None,
            },
            "uri": None,
            "request_headers": {},
            "request_method": None,
            "response_status_code": None,
        }

    @staticmethod
    def test_get_network_http():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nh = default_so.create_network_http()
        default_so.add_network_http(nh)
        assert default_so.get_network_http() == [nh]

    @staticmethod
    def test_create_signature():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        s = default_so.create_signature(name="blah", invalid="blah")
        assert s.name == "blah"

        normalized_so = SandboxOntology(normalize_paths=True)
        sig = normalized_so.create_signature()
        assert sig._normalize is True

    @staticmethod
    def test_add_signature():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        assert default_so.network_http == []

        s = default_so.create_signature()
        default_so.add_signature(s)
        assert default_so.signatures[0].as_primitives() == {
            "process": None,
            "name": None,
            "description": None,
            "attack": [],
            "iocs": [],
        }

    @staticmethod
    def test_get_signatures():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        sig = default_so.create_signature(name="blah")
        default_so.add_signature(sig)
        assert default_so.get_signatures()[0].name == "blah"

    @staticmethod
    def test_get_signatures_by_pid():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        sig = default_so.create_signature(name="blah")
        sig.update_process(pid=1)
        default_so.add_signature(sig)
        assert default_so.get_signatures_by_pid(1)[0].name == "blah"

    @staticmethod
    def test_set_sandbox_name():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        default_so.set_sandbox_name("blah")
        assert default_so.sandbox_name == "blah"

    @staticmethod
    def test_set_sandbox_version():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        default_so.set_sandbox_version("blah")
        assert default_so.sandbox_version == "blah"

    @staticmethod
    def test_sandbox_ontology_as_primitives():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

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
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so = SandboxOntology()
        p = so.create_process(pid=1, ppid=1, image="blah", command_line="blah", timestamp=1.0,
                              guid="{12345678-1234-5678-1234-567812345678}",
                              pguid="{12345678-1234-5678-1234-567812345679}")
        so.add_process(p)
        nc = so.create_network_connection(
            transport_layer_protocol="blah", source_ip="blah", source_port=1, destination_ip="blah", destination_port=1,
            timestamp=1.0, guid="{12345678-1234-5678-1234-567812345670}")
        so.add_network_connection(nc)
        actual_events = so.get_events()
        assert len(actual_events) == 2

    @staticmethod
    @pytest.mark.parametrize(
        "event_list, signatures, safelist, expected_result",
        [(None, None, [],
          []),
         ([],
          None, [],
          []),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1,
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}],
          None, [],
          [{'pid': 1, 'image': 'blah', 'tag': None,
            'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52', 'start_time': 1,
            'end_time': float("inf"),
            'guid': "{12345678-1234-5678-1234-567812345678}", 'ppid': 1,
            'pguid': "{12345678-1234-5678-1234-567812345679}", 'command_line': 'blah', 'pimage': None,
            'pcommand_line': None, 'children': [],
            "tag": None}]),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1,
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345678}"},
           {"pid": 2, "ppid": 1, "image": "blah2", "command_line": "blah2", "start_time": 2,
            "guid": "{12345678-1234-5678-1234-567812345679}", "pguid": "{12345678-1234-5678-1234-567812345678}"}],
          None, [],
          [{'pid': 1, 'image': 'blah', 'start_time': 1, 'end_time': float("inf"),
            'guid': "{12345678-1234-5678-1234-567812345678}", 'ppid': 1,
            'pguid': "{12345678-1234-5678-1234-567812345678}", 'command_line': 'blah', 'pimage': None,
            'pcommand_line': None, 'tag': None,
            'children':
            [{'pid': 2, 'image': 'blah2', 'start_time': 2, 'end_time': float("inf"),
              'guid': "{12345678-1234-5678-1234-567812345679}", 'ppid': 1,
              'pguid': "{12345678-1234-5678-1234-567812345678}", 'command_line': 'blah2', 'pimage': "blah",
              'pcommand_line': "blah", 'children': [],
              'tag': None, 'tree_id': '28fb5ed121e549f67b678d225bb2fc9971ed02c18a087f8fa9b05bf18a23d9e1'}],
            'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52'}]),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1,
            "guid": "{12345678-1234-5678-1234-567812345671}", "pguid": "{12345678-1234-5678-1234-567812345671}"},
           {"pid": 2, "ppid": 1, "image": "blah2", "command_line": "blah2", "start_time": 2,
            "guid": "{12345678-1234-5678-1234-567812345672}", "pguid": "{12345678-1234-5678-1234-567812345671}"},
           {"pid": 3, "ppid": 3, "image": "blah3", "command_line": "blah3", "start_time": 1,
            "guid": "{12345678-1234-5678-1234-567812345673}", "pguid": "{12345678-1234-5678-1234-567812345673}"},
           {"pid": 4, "ppid": 3, "image": "blah4", "command_line": "blah4", "start_time": 2,
            "guid": "{12345678-1234-5678-1234-567812345674}", "pguid": "{12345678-1234-5678-1234-567812345673}"}],
          None, ["55459caaa8ca94a90de5643a6a930e1b19bab480982607327081f46eb86f816c"],
          [{'pid': 1, 'image': 'blah', 'start_time': 1, 'end_time': float("inf"),
            'guid': "{12345678-1234-5678-1234-567812345671}", 'pguid': "{12345678-1234-5678-1234-567812345671}", 'ppid':
            1, 'command_line': 'blah', 'pimage': None, 'pcommand_line': None, 'tag': None,
            'children':
            [{'pid': 2, 'image': 'blah2', 'start_time': 2, 'end_time': float("inf"),
              'guid': "{12345678-1234-5678-1234-567812345672}", 'pguid': "{12345678-1234-5678-1234-567812345671}",
              'ppid': 1, 'command_line': 'blah2', 'children': [],
              'pimage': "blah", 'pcommand_line': "blah", 'tag': None,
              'tree_id': '28fb5ed121e549f67b678d225bb2fc9971ed02c18a087f8fa9b05bf18a23d9e1'}],
            'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52'}, ]),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1,
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}],
          [{"process.pid": 1, "name": "blah", "score": 1}],
          [],
          [{"children": [],
            "pid": 1, "ppid": 1, "image": "blah", 'pimage': None, 'pcommand_line': None, 'tag': None,
            'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52', "command_line": "blah",
            "start_time": 1, 'end_time': float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}]),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1,
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}],
          [{"process.pid": 1, "name": "blah", "score": 1}],
          [],
          [{"children": [],
            "pid": 2, "ppid": 1, "image": "blah", 'pimage': None, 'pcommand_line': None, 'tag': None,
            'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52', "command_line": "blah",
            "start_time": 1, 'end_time': float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}]),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1,
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}],
          [{"process.pid": 1, "name": "blah", "score": 1}],
          ["blah"],
          [{"children": [],
            "pid": 2, "ppid": 1, "image": "blah", 'pimage': None, 'pcommand_line': None, 'tag': None,
            'tree_id': '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52', "command_line": "blah",
            "start_time": 1, 'end_time': float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}]),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1,
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}],
          [{"process.pid": 1, "name": "blah", "score": 1}],
          ["8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52"],
          [])])
    def test_get_process_tree(event_list, signatures, safelist, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        o = SandboxOntology()
        if signatures:
            for signature in signatures:
                s = o.create_signature(**{k: v for k, v in signature.items() if "." not in k})
                s.update_process(**{k.split(".")[1]: v for k, v in signature.items() if "." in k})
                o.add_signature(s)
        if event_list:
            for event in event_list:
                p = o.create_process(**event)
                o.add_process(p)
        actual_result = o.get_process_tree(safelist=safelist)
        assert actual_result == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "event_list, signatures, safelist, correct_section_body",
        [(None, None, [],
          []),
         ([],
          None, [],
          []),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}],
          None, [],
          [{'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'signatures': {},
            'children': []}]),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"},
           {"pid": 2, "ppid": 1, "image": "blah2", "command_line": "blah2", "start_time": 2, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345679}", "pguid": "{12345678-1234-5678-1234-567812345678}"}],
          None, [],
          [{'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'signatures': {},
            'children':
            [{'process_pid': 2, 'process_name': 'blah2', 'command_line': 'blah2', 'signatures': {},
              'children': []}]}]),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345678}"},
           {"pid": 2, "ppid": 1, "image": "blah2", "command_line": "blah2", "start_time": 2, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345679}", "pguid": "{12345678-1234-5678-1234-567812345678}"},
           {"pid": 3, "ppid": 3, "image": "blah3", "command_line": "blah3", "start_time": 1, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345671}", "pguid": "{12345678-1234-5678-1234-567812345671}"},
           {"pid": 4, "ppid": 3, "image": "blah4", "command_line": "blah4", "start_time": 2, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345674}", "pguid": "{12345678-1234-5678-1234-567812345671}"}],
          None, ["55459caaa8ca94a90de5643a6a930e1b19bab480982607327081f46eb86f816c"],
          [{'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'signatures': {},
            'children':
            [{'process_pid': 2, 'process_name': 'blah2', 'command_line': 'blah2', 'signatures': {},
              'children': []}]}]),
         ([{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}],
          [{"process.pid": 1, "name": "blah", "score": 1}],
          [],
          [{'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'signatures': {'blah': 1},
            'children': []}]),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}],
          [{"process.pid": 1, "name": "blah", "score": 1}],
          [],
          [{'process_pid': 2, 'process_name': 'blah', 'command_line': 'blah', 'signatures': {},
            'children': []}]),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}],
          [{"process.pid": 1, "name": "blah", "score": 1}],
          ["blah"],
          [{'process_pid': 2, 'process_name': 'blah', 'command_line': 'blah', 'signatures': {},
            'children': []}]),
         ([{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "end_time": float("inf"),
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}"}],
          [{"process.pid": 1, "name": "blah", "score": 1}],
          ["8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52"],
          []), ])
    def test_get_process_tree_result_section(event_list, signatures, safelist, correct_section_body):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from assemblyline_v4_service.common.result import ResultProcessTreeSection
        o = SandboxOntology()
        nc = o.create_network_connection(
            **
            {"destination_ip": "1.1.1.1", "destination_port": 443, "source_ip": "2.2.2.2", "source_port": 9999,
             "transport_layer_protocol": "tcp"})
        nc.update_process(**{"pid": 4, "image": "blah4", "start_time": 3, "end_time": float("inf"),
                             "guid": "blah5", "pguid": "blah4"})
        o.add_network_connection(nc)
        if signatures:
            for signature in signatures:
                s = o.create_signature(**{k: v for k, v in signature.items() if "." not in k})
                s.update_process(**{k.split(".")[1]: v for k, v in signature.items() if "." in k})
                o.add_signature(s)
        if event_list:
            for event in event_list:
                p = o.create_process(**event)
                o.add_process(p)
        actual_result = o.get_process_tree_result_section(safelist=safelist)
        assert isinstance(actual_result, ResultProcessTreeSection)
        assert actual_result.section_body.__dict__["_data"] == correct_section_body

    @staticmethod
    def test_load_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        default_so.load_from_json({
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
                    "iocs": [
                        {
                            "ip": "blah",
                            "domain": None,
                            "uri": None,
                            "uri_path": None,
                            "process": None,
                        },
                        {
                            "ip": "blah",
                            "domain": None,
                            "uri": None,
                            "uri_path": None,
                            "process": {
                                "guid": "{12345678-1234-5678-1234-567812345678}",
                                "pguid": "{12345678-1234-5678-1234-567812345678}",
                                "pimage": "blah",
                                "pcommand_line": "blah",
                                "ppid": "blah",
                                "pid": "blah",
                                "image": "blah",
                                "command_line": "blah",
                                "start_time": "blah",
                                "end_time": "blah",
                                "tree_id": "blah",
                                "tag": "blah",
                            }
                        },
                    ],
                    "process": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "pguid": "{12345678-1234-5678-1234-567812345678}",
                        "pimage": "blah",
                        "pcommand_line": "blah",
                        "ppid": "blah",
                        "pid": "blah",
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": "blah",
                        "end_time": "blah",
                        "tree_id": "blah",
                        "tag": "blah",
                    }
                }
            ],
            "network_connections": [
                {
                    "guid": "{12345678-1234-5678-1234-567812345678}",
                    "source_ip": "blah",
                    "source_port": "blah",
                    "destination_ip": "blah",
                    "destination_port": "blah",
                    "transport_layer_protocol": "blah",
                    "direction": "blah",
                    "timestamp": "blah",
                    "tree_id": "blah",
                    "tag": "blah",
                    "process": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "pguid": "{12345678-1234-5678-1234-567812345678}",
                        "pimage": "blah",
                        "pcommand_line": "blah",
                        "ppid": "blah",
                        "pid": "blah",
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": "blah",
                        "end_time": "blah",
                        "tree_id": "blah",
                        "tag": "blah",
                    }
                }
            ],
            "network_dns": [
                {
                    "domain": "blah",
                    "resolved_ips": ["blah"],
                    "connection_details": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "source_ip": "blah",
                        "source_port": "blah",
                        "destination_ip": "blah",
                        "destination_port": "blah",
                        "transport_layer_protocol": "blah",
                        "direction": "blah",
                        "timestamp": "blah",
                        "tree_id": "blah",
                        "tag": "blah",
                        "process": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "pguid": "{12345678-1234-5678-1234-567812345678}",
                            "pimage": "blah",
                            "pcommand_line": "blah",
                            "ppid": "blah",
                            "pid": "blah",
                            "image": "blah",
                            "command_line": "blah",
                            "start_time": "blah",
                            "end_time": "blah",
                            "tree_id": "blah",
                            "tag": "blah",
                        }
                    }
                }
            ],
            "network_http": [
                {
                    "uri": "blah",
                    "request_headers": {"a": "b"},
                    "request_method": "blah",
                    "response_status_code": 123,
                    "connection_details": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "source_ip": "blah",
                        "source_port": "blah",
                        "destination_ip": "blah",
                        "destination_port": "blah",
                        "transport_layer_protocol": "blah",
                        "direction": "blah",
                        "timestamp": "blah",
                        "tree_id": "blah",
                        "tag": "blah",
                        "process": {
                            "guid": "{12345678-1234-5678-1234-567812345678}",
                            "pguid": "{12345678-1234-5678-1234-567812345678}",
                            "pimage": "blah",
                            "pcommand_line": "blah",
                            "ppid": "blah",
                            "pid": "blah",
                            "image": "blah",
                            "command_line": "blah",
                            "start_time": "blah",
                            "end_time": "blah",
                            "tree_id": "blah",
                            "tag": "blah",
                        }
                    }
                }
            ],
            "processes": [
                {
                    "guid": "{12345678-1234-5678-1234-567812345678}",
                    "pguid": "{12345678-1234-5678-1234-567812345678}",
                    "pimage": "blah",
                    "pcommand_line": "blah",
                    "ppid": "blah",
                    "pid": "blah",
                    "image": "blah",
                    "command_line": "blah",
                    "start_time": "blah",
                    "end_time": "blah",
                    "tree_id": "blah",
                    "tag": "blah",
                }
            ],
            "sandbox_name": "blah",
            "sandbox_version": "blah",
        })

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

        assert default_so.signatures[0].iocs[0].ip == "blah"
        assert default_so.signatures[0].iocs[0].domain is None
        assert default_so.signatures[0].iocs[0].uri is None
        assert default_so.signatures[0].iocs[0].uri_path is None
        assert default_so.signatures[0].iocs[0].process is None

        assert default_so.signatures[0].iocs[1].ip is None
        assert default_so.signatures[0].iocs[1].domain is None
        assert default_so.signatures[0].iocs[1].uri is None
        assert default_so.signatures[0].iocs[1].uri_path is None

        assert default_so.signatures[0].iocs[1].process.guid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.signatures[0].iocs[1].process.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.signatures[0].iocs[1].process.pimage == "blah"
        assert default_so.signatures[0].iocs[1].process.pcommand_line == "blah"
        assert default_so.signatures[0].iocs[1].process.ppid == "blah"
        assert default_so.signatures[0].iocs[1].process.pid == "blah"
        assert default_so.signatures[0].iocs[1].process.image == "blah"
        assert default_so.signatures[0].iocs[1].process.command_line == "blah"
        assert default_so.signatures[0].iocs[1].process.start_time == "blah"
        assert default_so.signatures[0].iocs[1].process.end_time == "blah"
        assert default_so.signatures[0].iocs[1].process.tree_id == "blah"
        assert default_so.signatures[0].iocs[1].process.tag == "blah"

        assert default_so.signatures[0]._normalize is False

        assert default_so.signatures[0].process.guid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.signatures[0].process.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.signatures[0].process.pimage == "blah"
        assert default_so.signatures[0].process.pcommand_line == "blah"
        assert default_so.signatures[0].process.ppid == "blah"
        assert default_so.signatures[0].process.pid == "blah"
        assert default_so.signatures[0].process.image == "blah"
        assert default_so.signatures[0].process.command_line == "blah"
        assert default_so.signatures[0].process.start_time == "blah"
        assert default_so.signatures[0].process.end_time == "blah"
        assert default_so.signatures[0].process.tree_id == "blah"
        assert default_so.signatures[0].process.tag == "blah"
        assert default_so.signatures[0].process._normalize is False

        assert default_so.network_connections[0].source_ip == "blah"
        assert default_so.network_connections[0].source_port == "blah"
        assert default_so.network_connections[0].destination_ip == "blah"
        assert default_so.network_connections[0].destination_port == "blah"
        assert default_so.network_connections[0].transport_layer_protocol == "blah"
        assert default_so.network_connections[0].direction == "blah"
        assert default_so.network_connections[0].tree_id == "blah"
        assert default_so.network_connections[0].tag == "blah"
        assert default_so.network_connections[0]._normalize is False

        assert default_so.network_connections[0].process.guid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.network_connections[0].process.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.network_connections[0].process.pimage == "blah"
        assert default_so.network_connections[0].process.pcommand_line == "blah"
        assert default_so.network_connections[0].process.ppid == "blah"
        assert default_so.network_connections[0].process.pid == "blah"
        assert default_so.network_connections[0].process.image == "blah"
        assert default_so.network_connections[0].process.command_line == "blah"
        assert default_so.network_connections[0].process.start_time == "blah"
        assert default_so.network_connections[0].process.end_time == "blah"
        assert default_so.network_connections[0].process.tree_id == "blah"
        assert default_so.network_connections[0].process.tag == "blah"
        assert default_so.network_connections[0].process._normalize is False

        assert default_so.network_dns[0].domain == "blah"
        assert default_so.network_dns[0].resolved_ips == ["blah"]

        assert default_so.network_dns[0].connection_details.source_ip == "blah"
        assert default_so.network_dns[0].connection_details.source_port == "blah"
        assert default_so.network_dns[0].connection_details.destination_ip == "blah"
        assert default_so.network_dns[0].connection_details.destination_port == "blah"
        assert default_so.network_dns[0].connection_details.transport_layer_protocol == "blah"
        assert default_so.network_dns[0].connection_details.direction == "blah"
        assert default_so.network_dns[0].connection_details.tree_id == "blah"
        assert default_so.network_dns[0].connection_details.tag == "blah"
        assert default_so.network_dns[0].connection_details._normalize is False

        assert default_so.network_dns[0].connection_details.process.guid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.network_dns[0].connection_details.process.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.network_dns[0].connection_details.process.pimage == "blah"
        assert default_so.network_dns[0].connection_details.process.pcommand_line == "blah"
        assert default_so.network_dns[0].connection_details.process.ppid == "blah"
        assert default_so.network_dns[0].connection_details.process.pid == "blah"
        assert default_so.network_dns[0].connection_details.process.image == "blah"
        assert default_so.network_dns[0].connection_details.process.command_line == "blah"
        assert default_so.network_dns[0].connection_details.process.start_time == "blah"
        assert default_so.network_dns[0].connection_details.process.end_time == "blah"
        assert default_so.network_dns[0].connection_details.process.tree_id == "blah"
        assert default_so.network_dns[0].connection_details.process.tag == "blah"
        assert default_so.network_dns[0].connection_details.process._normalize is False

        assert default_so.network_http[0].uri == "blah"
        assert default_so.network_http[0].request_headers == {"a": "b"}
        assert default_so.network_http[0].request_method == "blah"
        assert default_so.network_http[0].response_status_code == 123

        assert default_so.network_http[0].connection_details.source_ip == "blah"
        assert default_so.network_http[0].connection_details.source_port == "blah"
        assert default_so.network_http[0].connection_details.destination_ip == "blah"
        assert default_so.network_http[0].connection_details.destination_port == "blah"
        assert default_so.network_http[0].connection_details.transport_layer_protocol == "blah"
        assert default_so.network_http[0].connection_details.direction == "blah"
        assert default_so.network_http[0].connection_details.tree_id == "blah"
        assert default_so.network_http[0].connection_details.tag == "blah"
        assert default_so.network_http[0].connection_details._normalize is False

        assert default_so.network_http[0].connection_details.process.guid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.network_http[0].connection_details.process.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.network_http[0].connection_details.process.pimage == "blah"
        assert default_so.network_http[0].connection_details.process.pcommand_line == "blah"
        assert default_so.network_http[0].connection_details.process.ppid == "blah"
        assert default_so.network_http[0].connection_details.process.pid == "blah"
        assert default_so.network_http[0].connection_details.process.image == "blah"
        assert default_so.network_http[0].connection_details.process.command_line == "blah"
        assert default_so.network_http[0].connection_details.process.start_time == "blah"
        assert default_so.network_http[0].connection_details.process.end_time == "blah"
        assert default_so.network_http[0].connection_details.process.tree_id == "blah"
        assert default_so.network_http[0].connection_details.process.tag == "blah"
        assert default_so.network_http[0].connection_details.process._normalize is False

        assert default_so.processes[0].guid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.processes[0].pguid == "{12345678-1234-5678-1234-567812345678}"
        assert default_so.processes[0].pimage == "blah"
        assert default_so.processes[0].pcommand_line == "blah"
        assert default_so.processes[0].ppid == "blah"
        assert default_so.processes[0].pid == "blah"
        assert default_so.processes[0].image == "blah"
        assert default_so.processes[0].command_line == "blah"
        assert default_so.processes[0].start_time == "blah"
        assert default_so.processes[0].end_time == "blah"
        assert default_so.processes[0].tree_id == "blah"
        assert default_so.processes[0].tag == "blah"
        assert default_so.processes[0]._normalize is False

        assert default_so.sandbox_name == "blah"
        assert default_so.sandbox_version == "blah"

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

    @staticmethod
    def test_get_guids():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so = SandboxOntology()
        p = so.create_process(pid=1, start_time=0.0, end_time=1.0,
                              guid="{12345678-1234-5678-1234-567812345678}")
        so.add_process(p)
        assert so._get_guids() == ["{12345678-1234-5678-1234-567812345678}"]

    @staticmethod
    def test_validate_process():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from uuid import UUID
        so = SandboxOntology()

        # if not p.guid and p.pid not in pids:
        p1 = so.create_process(pid=1, start_time=0.0, end_time=1.0)
        assert so._validate_process(p1)
        assert UUID(p1.guid)
        so.add_process(p1)

        # else
        p2 = so.create_process(pid=2, start_time=0.0, end_time=1.0, guid="{12345678-1234-5678-1234-567812345678}")
        assert so._validate_process(p2)
        so.add_process(p2)

        # elif p.guid in guids and p.pid in pids:
        p3 = so.create_process(pid=2, start_time=0.0, end_time=1.0, guid="{12345678-1234-5678-1234-567812345678}")
        assert not so._validate_process(p3)

        # elif p.guid in guids and p.pid not in pids:
        p4 = so.create_process(pid=4, start_time=0.0, end_time=1.0, guid="{12345678-1234-5678-1234-567812345678}")
        assert not so._validate_process(p4)

        # elif p.guid not in guids and p.pid in pids:
        p5 = so.create_process(pid=3, start_time=1.0, end_time=2.0, guid="{87654321-1234-5678-1234-567812345678}")
        assert so._validate_process(p5)

    @staticmethod
    def test_handle_pid_match():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
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
    def test_load_process_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        p = default_so._load_process_from_json({
            "guid": "{12345678-1234-5678-1234-567812345678}",
            "pguid": "{12345678-1234-5678-1234-567812345678}",
            "pimage": "blah",
            "pcommand_line": "blah",
            "ppid": "blah",
            "pid": "blah",
            "image": "blah",
            "command_line": "blah",
            "start_time": "blah",
            "end_time": "blah",
            "tree_id": "blah",
            "tag": "blah",
        })
        assert p.guid == "{12345678-1234-5678-1234-567812345678}"
        assert p.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert p.pimage == "blah"
        assert p.pcommand_line == "blah"
        assert p.ppid == "blah"
        assert p.pid == "blah"
        assert p.image == "blah"
        assert p.command_line == "blah"
        assert p.start_time == "blah"
        assert p.end_time == "blah"
        assert p.tree_id == "blah"
        assert p.tag == "blah"
        assert p._normalize is False

    @staticmethod
    def test_load_signature_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        s = default_so._load_signature_from_json({
            "name": "blah",
            "description": "blah",
            "attack": [{'attack_id': 'T1187', 'categories': ['credential-access'], 'pattern': 'Forced Authentication'}],
            "iocs": [
                {
                    "ip": "blah",
                    "domain": None,
                    "uri": None,
                    "uri_path": None,
                    "process": None,
                },
                {
                    "ip": "blah",
                    "domain": None,
                    "uri": None,
                    "uri_path": None,
                    "process": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "pguid": "{12345678-1234-5678-1234-567812345678}",
                        "pimage": "blah",
                        "pcommand_line": "blah",
                        "ppid": "blah",
                        "pid": "blah",
                        "image": "blah",
                        "command_line": "blah",
                        "start_time": "blah",
                        "end_time": "blah",
                        "tree_id": "blah",
                        "tag": "blah",
                    }
                },
            ],
            "process": {
                "guid": "{12345678-1234-5678-1234-567812345678}",
                "pguid": "{12345678-1234-5678-1234-567812345678}",
                "pimage": "blah",
                "pcommand_line": "blah",
                "ppid": "blah",
                "pid": "blah",
                "image": "blah",
                "command_line": "blah",
                "start_time": "blah",
                "end_time": "blah",
                "tree_id": "blah",
                "tag": "blah",
            }
        })
        assert s.name == "blah"
        assert s.description == "blah"
        assert s.attack == [{'attack_id': 'T1187', 'categories': [
            'credential-access'], 'pattern': 'Forced Authentication'}]
        assert s.iocs[0].ip == "blah"
        assert s.iocs[0].domain is None
        assert s.iocs[0].uri is None
        assert s.iocs[0].uri_path is None
        assert s.iocs[0].process is None
        assert s.iocs[1].ip is None
        assert s.iocs[1].domain is None
        assert s.iocs[1].uri is None
        assert s.iocs[1].uri_path is None
        assert s.iocs[1].process.guid == "{12345678-1234-5678-1234-567812345678}"
        assert s.iocs[1].process.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert s.iocs[1].process.pimage == "blah"
        assert s.iocs[1].process.pcommand_line == "blah"
        assert s.iocs[1].process.ppid == "blah"
        assert s.iocs[1].process.pid == "blah"
        assert s.iocs[1].process.image == "blah"
        assert s.iocs[1].process.command_line == "blah"
        assert s.iocs[1].process.start_time == "blah"
        assert s.iocs[1].process.end_time == "blah"
        assert s.iocs[1].process.tree_id == "blah"
        assert s.iocs[1].process.tag == "blah"
        assert s._normalize is False
        assert s.process.guid == "{12345678-1234-5678-1234-567812345678}"
        assert s.process.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert s.process.pimage == "blah"
        assert s.process.pcommand_line == "blah"
        assert s.process.ppid == "blah"
        assert s.process.pid == "blah"
        assert s.process.image == "blah"
        assert s.process.command_line == "blah"
        assert s.process.start_time == "blah"
        assert s.process.end_time == "blah"
        assert s.process.tree_id == "blah"
        assert s.process.tag == "blah"
        assert s.process._normalize is False

    @staticmethod
    def test_load_network_connection_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nc = default_so._load_network_connection_from_json({
            "guid": "{12345678-1234-5678-1234-567812345678}",
            "source_ip": "blah",
            "source_port": "blah",
            "destination_ip": "blah",
            "destination_port": "blah",
            "transport_layer_protocol": "blah",
            "direction": "blah",
            "timestamp": "blah",
            "tree_id": "blah",
            "tag": "blah",
            "process": {
                "guid": "{12345678-1234-5678-1234-567812345678}",
                "pguid": "{12345678-1234-5678-1234-567812345678}",
                "pimage": "blah",
                "pcommand_line": "blah",
                "ppid": "blah",
                "pid": "blah",
                "image": "blah",
                "command_line": "blah",
                "start_time": "blah",
                "end_time": "blah",
                "tree_id": "blah",
                "tag": "blah",
            }
        })
        assert nc.source_ip == "blah"
        assert nc.source_port == "blah"
        assert nc.destination_ip == "blah"
        assert nc.destination_port == "blah"
        assert nc.transport_layer_protocol == "blah"
        assert nc.direction == "blah"
        assert nc.tree_id == "blah"
        assert nc.tag == "blah"
        assert nc._normalize is False
        assert nc.process.guid == "{12345678-1234-5678-1234-567812345678}"
        assert nc.process.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert nc.process.pimage == "blah"
        assert nc.process.pcommand_line == "blah"
        assert nc.process.ppid == "blah"
        assert nc.process.pid == "blah"
        assert nc.process.image == "blah"
        assert nc.process.command_line == "blah"
        assert nc.process.start_time == "blah"
        assert nc.process.end_time == "blah"
        assert nc.process.tree_id == "blah"
        assert nc.process.tag == "blah"
        assert nc.process._normalize is False

    @staticmethod
    def test_load_network_dns_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nd = default_so._load_network_dns_from_json({
            "domain": "blah",
            "resolved_ips": ["blah"],
            "connection_details": {
                "guid": "{12345678-1234-5678-1234-567812345678}",
                "source_ip": "blah",
                "source_port": "blah",
                "destination_ip": "blah",
                "destination_port": "blah",
                "transport_layer_protocol": "blah",
                "direction": "blah",
                "timestamp": "blah",
                "tree_id": "blah",
                "tag": "blah",
                "process": {
                    "guid": "{12345678-1234-5678-1234-567812345678}",
                    "pguid": "{12345678-1234-5678-1234-567812345678}",
                    "pimage": "blah",
                    "pcommand_line": "blah",
                    "ppid": "blah",
                    "pid": "blah",
                    "image": "blah",
                    "command_line": "blah",
                    "start_time": "blah",
                    "end_time": "blah",
                    "tree_id": "blah",
                    "tag": "blah",
                }
            }
        })
        assert nd.domain == "blah"
        assert nd.resolved_ips == ["blah"]
        assert nd.connection_details.source_ip == "blah"
        assert nd.connection_details.source_port == "blah"
        assert nd.connection_details.destination_ip == "blah"
        assert nd.connection_details.destination_port == "blah"
        assert nd.connection_details.transport_layer_protocol == "blah"
        assert nd.connection_details.direction == "blah"
        assert nd.connection_details.tree_id == "blah"
        assert nd.connection_details.tag == "blah"
        assert nd.connection_details._normalize is False
        assert nd.connection_details.process.guid == "{12345678-1234-5678-1234-567812345678}"
        assert nd.connection_details.process.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert nd.connection_details.process.pimage == "blah"
        assert nd.connection_details.process.pcommand_line == "blah"
        assert nd.connection_details.process.ppid == "blah"
        assert nd.connection_details.process.pid == "blah"
        assert nd.connection_details.process.image == "blah"
        assert nd.connection_details.process.command_line == "blah"
        assert nd.connection_details.process.start_time == "blah"
        assert nd.connection_details.process.end_time == "blah"
        assert nd.connection_details.process.tree_id == "blah"
        assert nd.connection_details.process.tag == "blah"
        assert nd.connection_details.process._normalize is False

    @staticmethod
    def test_load_network_http_from_json():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        nh = default_so._load_network_http_from_json({
            "uri": "blah",
            "request_headers": {"a": "b"},
            "request_method": "blah",
            "response_status_code": 123,
            "connection_details": {
                "guid": "{12345678-1234-5678-1234-567812345678}",
                "source_ip": "blah",
                "source_port": "blah",
                "destination_ip": "blah",
                "destination_port": "blah",
                "transport_layer_protocol": "blah",
                "direction": "blah",
                "timestamp": "blah",
                "tree_id": "blah",
                "tag": "blah",
                "process": {
                    "guid": "{12345678-1234-5678-1234-567812345678}",
                    "pguid": "{12345678-1234-5678-1234-567812345678}",
                    "pimage": "blah",
                    "pcommand_line": "blah",
                    "ppid": "blah",
                    "pid": "blah",
                    "image": "blah",
                    "command_line": "blah",
                    "start_time": "blah",
                    "end_time": "blah",
                    "tree_id": "blah",
                    "tag": "blah",
                }
            }
        })
        assert nh.uri == "blah"
        assert nh.request_headers == {"a": "b"}
        assert nh.request_method == "blah"
        assert nh.response_status_code == 123
        assert nh.connection_details.source_ip == "blah"
        assert nh.connection_details.source_port == "blah"
        assert nh.connection_details.destination_ip == "blah"
        assert nh.connection_details.destination_port == "blah"
        assert nh.connection_details.transport_layer_protocol == "blah"
        assert nh.connection_details.direction == "blah"
        assert nh.connection_details.tree_id == "blah"
        assert nh.connection_details.tag == "blah"
        assert nh.connection_details._normalize is False
        assert nh.connection_details.process.guid == "{12345678-1234-5678-1234-567812345678}"
        assert nh.connection_details.process.pguid == "{12345678-1234-5678-1234-567812345678}"
        assert nh.connection_details.process.pimage == "blah"
        assert nh.connection_details.process.pcommand_line == "blah"
        assert nh.connection_details.process.ppid == "blah"
        assert nh.connection_details.process.pid == "blah"
        assert nh.connection_details.process.image == "blah"
        assert nh.connection_details.process.command_line == "blah"
        assert nh.connection_details.process.start_time == "blah"
        assert nh.connection_details.process.end_time == "blah"
        assert nh.connection_details.process.tree_id == "blah"
        assert nh.connection_details.process.tag == "blah"
        assert nh.connection_details.process._normalize is False

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
                                 (
                                     [{"timestamp": 3}, {"start_time": 2}, {"timestamp": 1}],
                                     [{"timestamp": 1}, {"start_time": 2}, {"timestamp": 3}]
                                 ),
                             ]
                             )
    def test_sort_things_by_timestamp(things_to_sort_by_timestamp, expected_result, dummy_timestamp_class):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        dummy_things = []
        dummy_results = []
        if things_to_sort_by_timestamp is None:
            assert SandboxOntology._sort_things_by_timestamp(dummy_things) == []
            return

        actual_result = SandboxOntology._sort_things_by_timestamp(things_to_sort_by_timestamp)
        for index, item in enumerate(actual_result):
            assert item == expected_result[index]

        dummy_things = []
        dummy_results = []
        for thing in things_to_sort_by_timestamp:
            dummy_things.append(dummy_timestamp_class(thing))
        for result in expected_result:
            dummy_results.append(dummy_timestamp_class(result))
        actual_result = SandboxOntology._sort_things_by_timestamp(dummy_things)
        for index, item in enumerate(actual_result):
            assert item.__dict__ == dummy_results[index].__dict__

    @staticmethod
    @pytest.mark.parametrize("events, expected_events_dict",
                             [([{"pid": 1, "image": "blah", "start_time": 1, "guid": None, "pguid": None}],
                               {1:
                                {'guid': None, 'pguid': None, 'pimage': None, 'pcommand_line': None, 'ppid': None,
                                 'pid': 1, 'image': 'blah', 'command_line': None, 'start_time': 1, 'end_time': None,
                                 "tree_id": None, "tag": None}}),
                              ([{"pid": 1, "image": "blah", "start_time": 1, "guid": None, "pguid": None},
                                {"pid": 2, "image": "blah", "start_time": 1, "guid": None, "pguid": None}],
                               {1:
                                {'guid': None, 'pguid': None, 'pimage': None, 'pcommand_line': None, 'ppid': None,
                                 'pid': 1, 'image': 'blah', 'command_line': None, 'start_time': 1, 'end_time': None,
                                 "tree_id": None, "tag": None},
                                2:
                                {'guid': None, 'pguid': None, 'pimage': None, 'pcommand_line': None, 'ppid': None,
                                 'pid': 2, 'image': 'blah', 'command_line': None, 'start_time': 1, 'end_time': None,
                                 "tree_id": None, "tag": None}}),
                              ([{"pid": 1, "image": "blah", "start_time": 1,
                                 "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": None},
                                {"pid": 2, "image": "blah", "start_time": 1,
                                 "guid": "{12345678-1234-5678-1234-567812345679}", "pguid": None}],
                               {
                                  '{12345678-1234-5678-1234-567812345678}':
                                  {'guid': '{12345678-1234-5678-1234-567812345678}', 'pguid': None, 'pimage': None,
                                   'pcommand_line': None, 'ppid': None, 'pid': 1, 'image': 'blah', 'command_line': None,
                                   'start_time': 1, 'end_time': None, "tree_id": None, "tag": None},
                                  '{12345678-1234-5678-1234-567812345679}':
                                  {'guid': '{12345678-1234-5678-1234-567812345679}', 'pguid': None, 'pimage': None,
                                      'pcommand_line': None, 'ppid': None, 'pid': 2, 'image': 'blah', 'command_line': None,
                                      'start_time': 1, 'end_time': None, "tree_id": None, "tag": None}}), ])
    def test_convert_events_to_dict(events, expected_events_dict):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Process
        event_objects = [
            Process(
                pid=event["pid"],
                image=event["image"],
                start_time=event["start_time"],
                guid=event["guid"]) for event in events]
        assert SandboxOntology._convert_events_to_dict(event_objects) == expected_events_dict

    @staticmethod
    @pytest.mark.parametrize(
        "events_dict, expected_result",
        [
            # No processes
            ({}, []),
            # One process
            (
                {1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None}},
                [{"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                  "start_time": 1, "guid": None, "pguid": None, "children": []}]
            ),
            # One parent process and one child process
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah",
                     "command_line": "blah", "start_time": 1, "guid": None, "pguid": None,
                     "children": [{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "start_time": 1, "guid": None, "pguid": None, "children": []}]
                     },
                ],
            ),
            # Two unrelated processes
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                     "start_time": 1, "guid": None, "pguid": None, "children": []},
                    {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah",
                     "start_time": 1, "guid": None, "pguid": None, "children": []},
                ],
            ),
            # Three processes consisting of a parent-child relationship and a rando process
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None},
                    3: {"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                     "start_time": 1, "guid": None, "pguid": None, "children": []},
                    {"pid": 2, "ppid": 2, "image": "blah", "command_line": "blah",
                     "start_time": 1, "guid": None, "pguid": None,
                     "children": [{"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah",
                                   "start_time": 1, "guid": None, "pguid": None, "children": []}]
                     },
                ],
            ),
            # Three processes consisting of a grandparent-parent-child relationship and one rando process
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 2, "guid": None, "pguid": None},
                    3: {"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah", "start_time": 3, "guid": None, "pguid": None},
                    4: {"pid": 4, "ppid": 4, "image": "blah", "command_line": "blah", "start_time": 2, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                     "start_time": 1, "guid": None, "pguid": None,
                     "children": [{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "start_time": 2, "guid": None, "pguid": None,
                                   "children": [{"pid": 3, "ppid": 2, "image": "blah", "command_line": "blah",
                                                 "start_time": 3, "guid": None, "pguid": None,
                                                 "children": []}, ]}]
                     },
                    {"pid": 4, "ppid": 4, "image": "blah", "command_line": "blah",
                     "start_time": 2, "guid": None, "pguid": None, "children": []}
                ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 2, "guid": None, "pguid": None},
                    3: {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 3, "guid": None, "pguid": None},
                    4: {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "start_time": 4, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                     "start_time": 1, "guid": None, "pguid": None,
                     "children": [{"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "start_time": 2, "guid": None, "pguid": None,
                                   "children": [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah",
                                                 "start_time": 4,  "guid": None, "pguid": None,
                                                 "children": []}]},
                                  {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "start_time": 3,  "guid": None, "pguid": None,
                                   "children": []}
                                  ]
                     },
                ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship with non-ordered times
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None, "pguid": None},
                    2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 3, "guid": None, "pguid": None},
                    3: {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 2, "guid": None, "pguid": None},
                    4: {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "start_time": 4, "guid": None, "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                     "start_time": 1, "guid": None, "pguid": None,
                     "children": [{"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "start_time": 2, "guid": None, "pguid": None,
                                   "children": []},
                                  {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "start_time": 3, "guid": None, "pguid": None,
                                   "children": [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah",
                                                 "start_time": 4, "guid": None, "pguid": None,
                                                 "children": []}]},
                                  ]
                     },
                ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship
            # with non-ordered times using guids
            (
                {
                    "a": {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah",
                          "start_time": 1, "guid": "a", "pguid": None},
                    "b": {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                          "start_time": 3, "guid": "b", "pguid": "a"},
                    "c": {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah",
                          "start_time": 2, "guid": "c", "pguid": "a"},
                    "d": {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah",
                          "start_time": 4, "guid": "d", "pguid": "b"},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": "a",
                     "pguid": None,
                     "children": [{"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "start_time": 2, "guid": "c", "pguid": "a",
                                   "children": []},
                                  {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah",
                                   "start_time": 3, "guid": "b", "pguid": "a",
                                   "children": [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah",
                                                 "start_time": 4, "guid": "d", "pguid": "b",
                                                 "children": []}]},
                                  ]
                     },
                ],
            ),
            # Four processes consisting of a grandparent-parent-parent-child relationship
            # with non-ordered times using guids
            (
                {
                    1: {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None,
                                             "pguid": None},
                    2: {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 3, "guid": None,
                                             "pguid": None},
                    3: {"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 2, "guid": None,
                                             "pguid": None},
                    4: {"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah", "start_time": 4, "guid": None,
                                             "pguid": None},
                },
                [
                    {"pid": 1, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 1, "guid": None,
                     "pguid": None,
                     "children": [{"pid": 3, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 2,
                                  "guid": None, "pguid": None,
                                   "children": []},
                                  {"pid": 2, "ppid": 1, "image": "blah", "command_line": "blah", "start_time": 3,
                                  "guid": None, "pguid": None,
                                   "children": [{"pid": 4, "ppid": 2, "image": "blah", "command_line": "blah",
                                                "start_time": 4, "guid": None, "pguid": None, "children": []}]}, ]
                     },
                ],
            ),
        ]
    )
    def test_convert_events_dict_to_tree(events_dict, expected_result):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        actual_result = SandboxOntology._convert_events_dict_to_tree(events_dict)
        assert actual_result == expected_result

    @staticmethod
    def test_convert_event_tree_to_result_section():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so = SandboxOntology()
        actual_items = []
        event = {"pid": 1, "image": "blah", "command_line": "blah", "children": [
            {"pid": 2, "image": "blah", "command_line": "blah", "children": []}]}
        so._convert_event_tree_to_result_section(actual_items, event)
        assert actual_items[0].__dict__["pid"] == 1
        assert actual_items[0].__dict__["name"] == "blah"
        assert actual_items[0].__dict__["cmd"] == "blah"
        assert actual_items[0].__dict__["signatures"] == {}
        assert actual_items[0].__dict__["children"][0].__dict__ == {
            "name": "blah",
            "cmd": "blah",
            "pid": 2,
            "children": [],
            "signatures": {},

        }

    @staticmethod
    @pytest.mark.parametrize("parent, node, expected_node, expected_tree_ids",
                             [("",
                               {"image": "got the image", "guid": "{12345678-1234-5678-1234-567812345678}",
                                "children":
                                [{"image": "image number 2", "guid": "{12345678-1234-5678-1234-567812345679}",
                                  "children": []},
                                 {"image": "image number 3", "guid": "{12345678-1234-5678-1234-567812345670}",
                                  "children": []}]},
                               {"image": "got the image", "guid": "{12345678-1234-5678-1234-567812345678}",
                                "tree_id": "b71bf6eacf36ecdf07b3f1efa5d6f50725271ca85369b966e19da5b76c175b5b",
                                "children":
                                [{"image": "image number 2",
                                  "tree_id": "294156e02fb77c860933c93da8629dbceab367629a1ff9af68ff4b03c8596b17",
                                  "guid": "{12345678-1234-5678-1234-567812345679}", "children": []},
                                 {"image": "image number 3",
                                  "tree_id": "0483e740e929697527964c71227dd76403cdc91ca16e7a4a9a430f734481f129",
                                  "guid": "{12345678-1234-5678-1234-567812345670}", "children": []}]},
                               ["b71bf6eacf36ecdf07b3f1efa5d6f50725271ca85369b966e19da5b76c175b5b",
                                "294156e02fb77c860933c93da8629dbceab367629a1ff9af68ff4b03c8596b17",
                                "0483e740e929697527964c71227dd76403cdc91ca16e7a4a9a430f734481f129"]),
                              ("blahblah",
                               {"image": "got the image", "guid": "{12345678-1234-5678-1234-567812345678}",
                                "children":
                                [{"image": "image number 2", "guid": "{12345678-1234-5678-1234-567812345679}",
                                  "children": []},
                                 {"image": "image number 3", "guid": "{12345678-1234-5678-1234-567812345670}",
                                  "children": []}]},
                               {"image": "got the image",
                                "tree_id": "66ca3e01980a462ae88cf5e329ca479519f75d87192e93a8573e661bedb0cb9c",
                                "guid": "{12345678-1234-5678-1234-567812345678}",
                                "children":
                                [{"image": "image number 2",
                                  "tree_id": "9dc17d47ccef093c965c150401b717ba27728dd2c6360322526bd4c19493b154",
                                  "guid": "{12345678-1234-5678-1234-567812345679}", "children": []},
                                 {"image": "image number 3",
                                  "tree_id": "020951694e1d88b34a8a3409d1f6f027173302728800e000af9d874ff9a3004d",
                                  "guid": "{12345678-1234-5678-1234-567812345670}", "children": []}]},
                               ["66ca3e01980a462ae88cf5e329ca479519f75d87192e93a8573e661bedb0cb9c",
                                "9dc17d47ccef093c965c150401b717ba27728dd2c6360322526bd4c19493b154",
                                "020951694e1d88b34a8a3409d1f6f027173302728800e000af9d874ff9a3004d"])])
    def test_create_hashed_node(parent, node, expected_node, expected_tree_ids):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        default_so = SandboxOntology()
        p = default_so.create_process(guid="{12345678-1234-5678-1234-567812345678}", pid=1)
        p1 = default_so.create_process(guid="{12345678-1234-5678-1234-567812345679}", pid=2)
        p2 = default_so.create_process(guid="{12345678-1234-5678-1234-567812345670}", pid=3)
        default_so.add_process(p)
        default_so.add_process(p1)
        default_so.add_process(p2)

        default_so._create_hashed_node(parent, node)
        assert node == expected_node
        assert [proc.tree_id for proc in default_so.get_processes()] == expected_tree_ids

    @staticmethod
    @pytest.mark.parametrize("process_tree, expected_process_tree",
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
                                     "children": []}]}]}]), ])
    def test_create_tree_ids(process_tree, expected_process_tree):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        default_so = SandboxOntology()
        default_so._create_tree_ids(process_tree)
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
            assert expected_artifact.as_primitives(), actual_validated_artifact_list[index].as_primitives()

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
    def test_set_process_times():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        so = SandboxOntology()
        so.update_analysis_metadata(start_time=1.0, end_time=2.0)
        p = so.create_process(pid=1)
        so._set_process_times(p)
        assert p.start_time == 1.0
        assert p.end_time == 2.0

    @staticmethod
    def test_preprocess_ontology():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so = SandboxOntology()
        so.update_analysis_metadata(start_time=1.0, end_time=2.0)
        p = so.create_process(pid=1)
        so.add_process(p)
        so.preprocess_ontology()
        assert p.start_time == 1.0
        assert p.end_time == 2.0
