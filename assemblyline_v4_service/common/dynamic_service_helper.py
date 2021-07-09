from typing import List
from re import compile
from logging import getLogger
from assemblyline.common import log as al_log
from assemblyline_v4_service.common.result import ResultSection, Heuristic
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import MaxExtractedExceeded

HOLLOWSHUNTER_EXE_REGEX = "[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.exe$"
HOLLOWSHUNTER_SHC_REGEX = "[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.shc$"
HOLLOWSHUNTER_DLL_REGEX = "[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.dll$"

al_log.init_logging('service.dynamic_service_helper')
log = getLogger('assemblyline.service.dynamic_service_helper')


class Event:
    def __init__(self, pid: int = None, image: str = None, timestamp: float = None, guid: str = None):
        self.pid = pid
        self.image = image
        self.timestamp = timestamp
        self.guid = guid

    def convert_event_to_dict(self) -> dict:
        return self.__dict__


class ProcessEvent(Event):
    def __init__(self, pid: int = None, ppid: int = None, image: str = None, command_line: str = None,
                 timestamp: float = None, guid: str = None):
        super().__init__(pid=pid, image=image, timestamp=timestamp, guid=guid)
        self.ppid = ppid
        self.command_line = command_line

    @staticmethod
    def keys() -> set:
        return {"command_line", "guid", "image", "pid", "ppid", "timestamp"}


class NetworkEvent(Event):
    def __init__(self, protocol: str = None, src_ip: str = None, src_port: int = None, domain: str = None,
                 dest_ip: str = None, dest_port: int = None, pid: int = None, image: str = None,
                 timestamp: float = None, guid: str = None):
        super().__init__(pid=pid, image=image, timestamp=timestamp, guid=guid)
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.domain = domain
        self.dest_ip = dest_ip
        self.dest_port = dest_port

    @staticmethod
    def keys() -> set:
        return {"dest_ip", "dest_port", "domain", "guid", "image", "pid", "protocol", "src_ip", "src_port", "timestamp"}


class Events:
    def __init__(self, events: List[dict] = None):
        if events is None:
            self.events = []
            self.sorted_events = []
            self.process_events = []
            self.process_event_dicts = {}
            self.network_events = []
            self.network_event_dicts = {}
        else:
            self.events = self._validate_events(events)
            self.sorted_events = self._sort_things_by_timestamp(self.events)
            self.process_events = self._get_process_events(self.sorted_events)
            self.process_event_dicts = self._convert_events_to_dict(self.process_events)
            self.network_events = self._get_network_events(self.sorted_events)
            self.network_event_dicts = self._convert_events_to_dict(self.network_events)

    @staticmethod
    def _validate_events(events: List[dict] = None) -> List[Event]:
        validated_events = []
        process_event_keys = ProcessEvent.keys()
        network_event_keys = NetworkEvent.keys()
        for event in events:
            event_keys = set(event.keys())
            if event_keys == process_event_keys:
                validated_process_event = ProcessEvent(
                    pid=event["pid"],
                    ppid=event["ppid"],
                    image=event["image"],
                    command_line=event["command_line"],
                    timestamp=event["timestamp"],
                    guid=event["guid"],
                )
                validated_events.append(validated_process_event)
            elif event_keys == network_event_keys:
                validated_network_event = NetworkEvent(
                    protocol=event["protocol"],
                    src_ip=event["src_ip"],
                    src_port=event["src_port"],
                    domain=event["domain"],
                    dest_ip=event["dest_ip"],
                    dest_port=event["dest_port"],
                    pid=event["pid"],
                    image=event["image"],
                    timestamp=event["timestamp"],
                    guid=event["guid"],
                )
                validated_events.append(validated_network_event)
            else:
                raise ValueError(f"The event {event} does not match the process_event format {process_event_keys} or the network_event format {network_event_keys}.")
        return validated_events

    @staticmethod
    def _get_process_events(events: List[Event] = None) -> List[ProcessEvent]:
        process_events = []
        for event in events:
            if isinstance(event, ProcessEvent):
                process_events.append(event)
        return process_events

    @staticmethod
    def _get_network_events(events: List[Event] = None) -> List[NetworkEvent]:
        network_events = []
        for event in events:
            if isinstance(event, NetworkEvent):
                network_events.append(event)
        return network_events

    @staticmethod
    def _sort_things_by_timestamp(things_to_sort_by_timestamp: List = None) -> List:
        if not things_to_sort_by_timestamp:
            return []
        if isinstance(things_to_sort_by_timestamp[0], dict):
            timestamp = lambda x: x["timestamp"]
        else:
            timestamp = lambda x: x.timestamp
        sorted_things = sorted(things_to_sort_by_timestamp, key=timestamp)
        return sorted_things

    @staticmethod
    def _convert_events_to_dict(events: List[Event]) -> dict:
        events_dict = {}
        for event in events:
            events_dict[event.pid] = event.convert_event_to_dict()
        return events_dict


class Artefact:
    def __init__(self, name: str = None, path: str = None, description: str = None, to_be_extracted: bool = None):
        if any(item is None for item in [name, path, description, to_be_extracted]):
            raise Exception("Missing positional arguments for Artefact validation")

        self.name = name
        self.path = path
        self.description = description
        self.to_be_extracted = to_be_extracted


class Signature:
    def __init__(self, pid: int = None, name: str = None, score: int = None):
        self.pid = pid
        self.name = name
        self.score = score

    @staticmethod
    def keys() -> set:
        return {"name", "pid", "score"}

    def convert_signature_to_dict(self) -> dict:
        return self.__dict__


class Signatures:
    def __init__(self, signatures: List[dict] = None):
        if signatures is None:
            signatures = []
        self.signatures = self._validate_signatures(signatures)
        self.signature_dicts = self._convert_signatures_to_dicts()

    @staticmethod
    def _validate_signatures(signatures: List[dict] = None) -> List[Signature]:
        signature_keys = Signature.keys()
        validated_signatures = []
        for signature in signatures:
            if set(signature.keys()) == signature_keys:
                validated_signature = Signature(
                    pid=signature["pid"],
                    name=signature["name"],
                    score=signature["score"],
                )
                validated_signatures.append(validated_signature)
            else:
                raise ValueError(f"{signature} does not match the signature format of {signature_keys}")
        return validated_signatures

    def _convert_signatures_to_dicts(self) -> List[dict]:
        signature_dicts = []
        for signature in self.signatures:
            signature_dict = signature.convert_signature_to_dict()
            signature_dicts.append(signature_dict)
        return signature_dicts


class SandboxOntology(Events):
    def __init__(self, events: List[dict] = None):
        Events.__init__(self, events=events)

    @staticmethod
    def _convert_processes_dict_to_tree(processes_dict: dict = None) -> List[dict]:
        root = {
            "children": [],
        }
        sorted_processes = SandboxOntology._sort_things_by_timestamp(list(processes_dict.values()))
        procs_seen = []

        for p in sorted_processes:
            p["children"] = []
            if p["ppid"] in procs_seen:
                processes_dict[p["ppid"]]["children"].append(p)
            else:
                root["children"].append(p)

            procs_seen.append(p["pid"])

        return SandboxOntology._sort_things_by_timestamp(root["children"])

    @staticmethod
    def _validate_artefacts(artefact_list: List[dict] = None) -> List[Artefact]:
        if artefact_list is None:
            artefact_list = []

        validated_artefacts = []
        for artefact in artefact_list:
            validated_artefact = Artefact(
                name=artefact["name"],
                path=artefact["path"],
                description=artefact["description"],
                to_be_extracted=artefact["to_be_extracted"]
            )
            validated_artefacts.append(validated_artefact)
        return validated_artefacts

    @staticmethod
    def _handle_artefact(artefact: Artefact = None, artefacts_result_section: ResultSection = None):
        if artefact is None:
            raise Exception("Artefact cannot be None")

        # This is a dict who's key-value pairs follow the format {regex: result_section_title}
        artefact_map = {
            HOLLOWSHUNTER_EXE_REGEX: "HollowsHunter Injected Portable Executable",
            HOLLOWSHUNTER_SHC_REGEX: "HollowsHunter Shellcode",
            HOLLOWSHUNTER_DLL_REGEX: "HollowsHunter DLL",
        }
        artefact_result_section = None

        for regex, title in artefact_map.items():
            pattern = compile(regex)
            if pattern.match(artefact.name):
                artefact_result_section = ResultSection(title)
                artefact_result_section.add_tag("dynamic.process.file_name", artefact.path)
                if regex in [HOLLOWSHUNTER_EXE_REGEX]:
                    # As of right now, heuristic ID 17 is associated with the Injection category in the Cuckoo service
                    heur = Heuristic(17)
                    heur.add_signature_id("hollowshunter_pe")
                    artefact_result_section.heuristic = heur

        if artefact_result_section is not None:
            artefacts_result_section.add_subsection(artefact_result_section)

    def _match_signatures_to_process_events(self, signature_dicts: List[dict]) -> dict:
        process_event_dicts_with_signatures = {}
        copy_of_process_event_dicts = self.process_event_dicts.copy()
        for pid, process_event_dict in copy_of_process_event_dicts.items():
            process_event_dict["signatures"] = {}
            process_event_dicts_with_signatures[pid] = process_event_dict

            # Match the UI ProcessTree result body format
            process_event_dict["process_pid"] = process_event_dict["pid"]
            process_event_dict["process_name"] = process_event_dict["image"]
            # NOTE: not going to delete the original of the duplicated keys, as they may be useful in the future

        for signature_dict in signature_dicts:
            pid = signature_dict["pid"]
            name = signature_dict["name"]
            score = signature_dict["score"]
            if pid not in process_event_dicts_with_signatures:
                # Ignore it
                log.warning(f"{signature_dict} does not match up with a PID in {process_event_dicts_with_signatures.keys()}")
            else:
                process_event_dicts_with_signatures[pid]["signatures"][name] = score

        return process_event_dicts_with_signatures

    def get_process_tree(self) -> List[dict]:
        process_tree = self._convert_processes_dict_to_tree(self.process_event_dicts)
        return process_tree

    def get_process_tree_with_signatures(self, signatures: List[dict] = None) -> List[dict]:
        if signatures is None:
            signatures = []
        s = Signatures(signatures=signatures)
        process_event_dicts_with_signatures = self._match_signatures_to_process_events(s.signature_dicts)
        process_tree_with_signatures = self._convert_processes_dict_to_tree(process_event_dicts_with_signatures)
        return process_tree_with_signatures

    def get_events(self) -> List[dict]:
        sorted_event_dicts = []
        for event in self.sorted_events:
            sorted_event_dicts.append(event.convert_event_to_dict())
        return sorted_event_dicts

    def run_signatures(self) -> ResultSection:
        """
        Runs signatures against class attribute processes, and returns a ResultSection with the details
        """
        raise NotImplementedError

    @staticmethod
    def handle_artefacts(artefact_list: list, request: ServiceRequest) -> ResultSection:
        """
        Goes through each artefact in artefact_list, uploading them and adding result sections accordingly

        Positional arguments:
        artefact_list -- list of dictionaries that each represent an artefact
        """

        validated_artefacts = SandboxOntology._validate_artefacts(artefact_list)

        artefacts_result_section = ResultSection("Sandbox Artefacts")

        for artefact in validated_artefacts:
            SandboxOntology._handle_artefact(artefact, artefacts_result_section)

            if artefact.to_be_extracted:
                try:
                    request.add_extracted(artefact.path, artefact.name, artefact.description)
                except MaxExtractedExceeded:
                    # To avoid errors from being raised when too many files have been extracted
                    pass
            else:
                request.add_supplementary(artefact.path, artefact.name, artefact.description)

        return artefacts_result_section if artefacts_result_section.subsections else None
