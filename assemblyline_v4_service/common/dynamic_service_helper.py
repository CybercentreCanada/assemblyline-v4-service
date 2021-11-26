from typing import Dict, List, Optional, Any
from re import compile, escape, sub
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
    X86_64 = "x86_64"
    X86 = "x86"

    def __init__(self, pid: int = None, image: str = None, timestamp: float = None, guid: str = None):
        self.pid = pid
        self.image = image
        self.timestamp = timestamp
        self.guid = guid

    def convert_event_to_dict(self) -> Dict[str, Any]:
        return self.__dict__

    def _determine_arch(self, path: str) -> str:
        # Clear indicators in a file path of the architecture of the operating system
        if any(item in path for item in ["program files (x86)", "syswow64"]):
            return self.X86_64
        return self.X86

    @staticmethod
    def _pattern_substitution(path: str, rule: Dict[str, str]) -> str:
        if path.startswith(rule['pattern']):
            path = path.replace(rule['pattern'], rule['replacement'])
        return path

    @staticmethod
    def _regex_substitution(path: str, rule: Dict[str, str]) -> str:
        rule['regex'] = rule['regex'].split('*')
        rule['regex'] = [escape(e) for e in rule['regex']]
        rule['regex'] = '[^\\\\]+'.join(rule['regex'])
        path = sub(rf"{rule['regex']}", rule['replacement'], path)
        return path

    def _normalize_path(self, path: str, arch: Optional[str] = None) -> str:
        path = path.lower()
        if not arch:
            arch = self._determine_arch(path)

        system_drive = 'c:\\'
        system_root = 'c:\\windows\\'
        sz_usr_temp_path = 'users\\*\\appdata\\local\\temp\\'
        sz_usr_path = 'users\\*\\'
        arch_specific_defaults = {
            self.X86_64: {
                'szProgFiles86': 'program files (x86)',
                'szProgFiles64': 'program files',
                'szSys86': 'syswow64',
                'szSys64': 'system32'
            },
            self.X86: {
                'szProgFiles86': 'program files',
                'szSys86': 'system32'
            }
        }

        # Order here matters
        rules: List[Dict[str, str]] = []
        rules.append({
            'pattern': system_root + arch_specific_defaults[arch]["szSys86"],
            'replacement': '?sys32'
        })
        if arch == self.X86_64:
            rules.append({
                'pattern': system_root + arch_specific_defaults[arch]["szSys64"],
                'replacement': '?sys64'
            })
        rules.append({
            'pattern': system_drive + arch_specific_defaults[arch]["szProgFiles86"],
            'replacement': '?pf86'
        })
        if arch == self.X86_64:
            rules.append({
                'pattern': system_drive + arch_specific_defaults[arch]["szProgFiles64"],
                'replacement': '?pf64'
            })
        rules.append({
            'regex': f"{system_drive}{sz_usr_temp_path}",
            'replacement': '?usrtmp\\\\'
        })
        rules.append({
            'regex': f"{system_drive}{sz_usr_path}",
            'replacement': '?usr\\\\'
        })
        rules.append({
            'pattern': system_root,
            'replacement': '?win\\'
        })
        rules.append({
            'pattern': system_drive,
            'replacement': '?c\\'
        })
        for rule in rules:
            if 'pattern' in rule:
                path = self._pattern_substitution(path, rule)
            if 'regex' in rule:
                path = self._regex_substitution(path, rule)
        return path

    def normalize_paths(self, attributes: List[str]):
        for attribute in attributes:
            if hasattr(self, attribute):
                setattr(self, attribute, self._normalize_path(getattr(self, attribute)))
            else:
                raise ValueError(f"{self.__class__} does not have attribute '{attribute}'")
        return self


class ProcessEvent(Event):
    def __init__(self, pid: int = None, ppid: int = None, image: str = None, command_line: str = None,
                 timestamp: float = None, guid: str = None, pguid: str = None):
        super().__init__(pid=pid, image=image, timestamp=timestamp, guid=guid)
        self.ppid = ppid
        self.pguid = pguid
        self.command_line = command_line

    @staticmethod
    def keys() -> set:
        return {"command_line", "guid", "image", "pid", "pguid", "ppid", "timestamp"}


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
    def __init__(self, events: List[Dict[str, Any]] = None, normalize_paths: bool = False):
        self.normalize_paths = normalize_paths
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
            self.process_events = self._get_process_events(self.sorted_events, self.normalize_paths)
            self.process_event_dicts = self._convert_events_to_dict(self.process_events)
            self.network_events = self._get_network_events(self.sorted_events)
            self.network_event_dicts = self._convert_events_to_dict(self.network_events)

    @staticmethod
    def _validate_events(events: List[Dict[str, Any]] = None) -> List[Event]:
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
                    pguid=event["pguid"],
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
    def _get_process_events(events: List[Event] = None, normalize_paths: bool = False) -> List[ProcessEvent]:
        process_events = []
        for event in events:
            if isinstance(event, ProcessEvent):
                if normalize_paths:
                    event = event.normalize_paths(["image"])
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
    def _sort_things_by_timestamp(things_to_sort_by_timestamp: List[Any] = None) -> List[Any]:
        if not things_to_sort_by_timestamp:
            return []
        if isinstance(things_to_sort_by_timestamp[0], Dict):
            timestamp = lambda x: x["timestamp"]
        else:
            timestamp = lambda x: x.timestamp
        sorted_things = sorted(things_to_sort_by_timestamp, key=timestamp)
        return sorted_things

    @staticmethod
    def _convert_events_to_dict(events: List[Event]) -> Dict[str, Any]:
        events_dict = {}
        mapping_value = "pid"
        if all([event.guid is not None for event in events]):
            mapping_value = "guid"
        for event in events:
            events_dict[getattr(event, mapping_value)] = event.convert_event_to_dict()
        return events_dict


class Artifact:
    def __init__(self, name: str = None, path: str = None, description: str = None, to_be_extracted: bool = None):
        if any(item is None for item in [name, path, description, to_be_extracted]):
            raise Exception("Missing positional arguments for Artifact validation")

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

    def convert_signature_to_dict(self) -> Dict:
        return self.__dict__


class Signatures:
    def __init__(self, signatures: List[Dict[str, Any]] = None):
        if signatures is None:
            signatures = []
        self.signatures = self._validate_signatures(signatures)
        self.signature_dicts = self._convert_signatures_to_dicts()

    @staticmethod
    def _validate_signatures(signatures: List[Dict[str, Any]] = None) -> List[Signature]:
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

    def _convert_signatures_to_dicts(self) -> List[Dict[str, Any]]:
        signature_dicts = []
        for signature in self.signatures:
            signature_dict = signature.convert_signature_to_dict()
            signature_dicts.append(signature_dict)
        return signature_dicts


class SandboxOntology(Events):
    def __init__(self, events: List[Dict[str, Any]] = None, normalize_paths: bool = False):
        Events.__init__(self, events=events, normalize_paths=normalize_paths)

    @staticmethod
    def _convert_processes_dict_to_tree(processes_dict: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        root = {
            "children": [],
        }
        sorted_processes = SandboxOntology._sort_things_by_timestamp(list(processes_dict.values()))
        procs_seen = []
        key_to_use_for_linking = "ppid"
        key_to_use_for_tracking = "pid"
        if all([any(process_dict.get(key) for key in ["pguid", "guid"]) for process_dict in processes_dict.values()]):
            key_to_use_for_linking = "pguid"
            key_to_use_for_tracking = "guid"

        for p in sorted_processes:
            # Match the UI ProcessTree result body format
            p["process_pid"] = p["pid"]
            p["process_name"] = p["image"]
            # NOTE: not going to delete the original of the duplicated keys, as they may be useful in the future

            p["children"] = []
            if p[key_to_use_for_linking] in procs_seen:
                processes_dict[p[key_to_use_for_linking]]["children"].append(p)
            else:
                root["children"].append(p)

            procs_seen.append(p[key_to_use_for_tracking])

        return SandboxOntology._sort_things_by_timestamp(root["children"])

    @staticmethod
    def _validate_artifacts(artifact_list: List[Dict[str, Any]] = None) -> List[Artifact]:
        if artifact_list is None:
            artifact_list = []

        validated_artifacts = []
        for artifact in artifact_list:
            validated_artifact = Artifact(
                name=artifact["name"],
                path=artifact["path"],
                description=artifact["description"],
                to_be_extracted=artifact["to_be_extracted"]
            )
            validated_artifacts.append(validated_artifact)
        return validated_artifacts

    @staticmethod
    def _handle_artifact(artifact: Artifact = None, artifacts_result_section: ResultSection = None):
        if artifact is None:
            raise Exception("Artifact cannot be None")

        # This is a dict who's key-value pairs follow the format {regex: result_section_title}
        artifact_map = {
            HOLLOWSHUNTER_EXE_REGEX: "HollowsHunter Injected Portable Executable",
            HOLLOWSHUNTER_DLL_REGEX: "HollowsHunter DLL",
        }
        artifact_result_section = None

        for regex, title in artifact_map.items():
            pattern = compile(regex)
            if pattern.match(artifact.name):
                artifact_result_section = ResultSection(title)
                artifact_result_section.add_tag("dynamic.process.file_name", artifact.path)
                if regex in [HOLLOWSHUNTER_EXE_REGEX]:
                    # As of right now, heuristic ID 17 is associated with the Injection category in the Cuckoo service
                    heur = Heuristic(17)
                    heur.add_signature_id("hollowshunter_pe")
                    artifact_result_section.heuristic = heur

        if artifact_result_section is not None:
            artifacts_result_section.add_subsection(artifact_result_section)

    def _match_signatures_to_process_events(self, signature_dicts: List[Dict[str, Any]]) -> Dict[str, Any]:
        process_event_dicts_with_signatures = {}
        copy_of_process_event_dicts = self.process_event_dicts.copy()
        for key, process_event_dict in copy_of_process_event_dicts.items():
            process_event_dict["signatures"] = {}
            process_event_dicts_with_signatures[key] = process_event_dict

        pids = [process_event_dict["pid"] for process_event_dict in copy_of_process_event_dicts.values()]
        for signature_dict in signature_dicts:
            pid = signature_dict["pid"]
            name = signature_dict["name"]
            score = signature_dict["score"]
            if pid not in pids:
                # Ignore it
                log.warning(f"{signature_dict} does not match up with a PID in {process_event_dicts_with_signatures.keys()}")
            else:
                # We should always get a key from this
                key = next(key for key, process_event_dict in process_event_dicts_with_signatures.items() if process_event_dict["pid"] == pid)
                process_event_dicts_with_signatures[key]["signatures"][name] = score

        return process_event_dicts_with_signatures

    def get_process_tree(self) -> List[Dict[str, Any]]:
        process_tree = self._convert_processes_dict_to_tree(self.process_event_dicts)
        return process_tree

    def get_process_tree_with_signatures(self, signatures: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if signatures is None:
            signatures = []
        s = Signatures(signatures=signatures)
        process_event_dicts_with_signatures = self._match_signatures_to_process_events(s.signature_dicts)
        process_tree_with_signatures = self._convert_processes_dict_to_tree(process_event_dicts_with_signatures)
        return process_tree_with_signatures

    def get_events(self) -> List[Dict[str, Any]]:
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
    def handle_artifacts(artifact_list: List[Dict[str, Any]], request: ServiceRequest) -> ResultSection:
        """
        Goes through each artifact in artifact_list, uploading them and adding result sections accordingly

        Positional arguments:
        artifact_list -- list of dictionaries that each represent an artifact
        """

        validated_artifacts = SandboxOntology._validate_artifacts(artifact_list)

        artifacts_result_section = ResultSection("Sandbox Artifacts")

        for artifact in validated_artifacts:
            SandboxOntology._handle_artifact(artifact, artifacts_result_section)

            if artifact.to_be_extracted:
                try:
                    request.add_extracted(artifact.path, artifact.name, artifact.description)
                except MaxExtractedExceeded:
                    # To avoid errors from being raised when too many files have been extracted
                    pass
            else:
                request.add_supplementary(artifact.path, artifact.name, artifact.description)

        return artifacts_result_section if artifacts_result_section.subsections else None
