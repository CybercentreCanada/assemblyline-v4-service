from typing import Dict, List, Optional, Any, Union, Set
from re import compile, escape, sub
from logging import getLogger
from assemblyline.common import log as al_log
from assemblyline_v4_service.common.result import ResultSection, ProcessItem, NetworkItem, ResultProcessTreeSection, NETWORK_TYPE, PROCESS_TYPE
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import MaxExtractedExceeded
from hashlib import sha256

HOLLOWSHUNTER_EXE_REGEX = r"[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.exe$"
HOLLOWSHUNTER_SHC_REGEX = r"[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.shc$"
HOLLOWSHUNTER_DLL_REGEX = r"[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.dll$"

HOLLOWSHUNTER_TITLE = "HollowsHunter Injected Portable Executable"

# Tree Types
PROCESS = "PROCESS"
NETWORK = "NETWORK"
EVENT = "EVENT"

al_log.init_logging('service.dynamic_service_helper')
log = getLogger('assemblyline.service.dynamic_service_helper')


class Event:
    """
    This class represents an event that takes place on an operating system and includes key details about that event
    """
    X86_64 = "x86_64"
    X86 = "x86"

    SYSTEM_DRIVE = 'c:\\'
    SYSTEM_ROOT = 'c:\\windows\\'
    SZ_USR_TEMP_PATH = 'users\\*\\appdata\\local\\temp\\'
    SZ_USR_PATH = 'users\\*\\'
    ARCH_SPECIFIC_DEFAULTS = {
        X86_64: {
            'szProgFiles86': 'program files (x86)',
            'szProgFiles64': 'program files',
            'szSys86': 'syswow64',
            'szSys64': 'system32'
        },
        X86: {
            'szProgFiles86': 'program files',
            'szSys86': 'system32'
        }
    }

    def __init__(self, pid: int = None, image: str = None, timestamp: float = None, guid: str = None, pguid: str = None) -> None:
        """
        This method initializes an Event object
        :param pid: The process ID associated with the event
        :param image: The name of the executable file associated with the event
        :param timestamp: The time at which the event occurred
        :param guid: The unique identifier for the event
        :param pguid: The unique identifier for the parent process that spawned this event
        :return: None
        """
        self.pid = pid
        self.image = image
        self.timestamp = timestamp
        self.guid = guid
        self.pguid = pguid
        self.signatures = {}
        self.children = []
        self.tree_id = None

    def convert_event_to_dict(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the event object
        :return: The dictionary representation of the event object
        """
        return self.__dict__

    @staticmethod
    def keys() -> Set[str]:
        """
        This method returns the class attributes / keys of the dictionary representation of the event object
        :return: The class attributes / keys of the dictionary representation of the event object
        """
        return {"pid", "image", "timestamp", "guid", "pguid", "signatures", "children", "tree_id"}

    def _determine_arch(self, path: str) -> str:
        """
        This method determines what architecture the operating system was built with where the event took place
        :param path: The file path of the image associated with an event
        :return: The architecture of the operating system
        """
        # Clear indicators in a file path of the architecture of the operating system
        if any(item in path for item in ["program files (x86)", "syswow64"]):
            return self.X86_64
        return self.X86

    @staticmethod
    def _pattern_substitution(path: str, rule: Dict[str, str]) -> str:
        """
        This method applies pattern rules for explicit string substitution
        :param path: The file path of the image associated with an event
        :param rule: The rule to be applied, containing a pattern and the replacement value
        :return: The modified path, if any rules applied
        """
        if path.startswith(rule['pattern']):
            path = path.replace(rule['pattern'], rule['replacement'])
        return path

    @staticmethod
    def _regex_substitution(path: str, rule: Dict[str, str]) -> str:
        """
        This method applies a regular expression for implicit string substitution
        :param path: The file path of the image associated with an event
        :param rule: The rule to be applied, containing a pattern and the replacement value
        :return: The modified path, if any rules applied
        """
        rule['regex'] = rule['regex'].split('*')
        rule['regex'] = [escape(e) for e in rule['regex']]
        rule['regex'] = '[^\\\\]+'.join(rule['regex'])
        path = sub(rf"{rule['regex']}", rule['replacement'], path)
        return path

    def _normalize_path(self, path: str, arch: Optional[str] = None) -> str:
        """
        This method determines what rules should be applied based on architecture and the applies the rules to the path
        :param path: The file path of the image associated with an event
        :param arch: The architecture of the operating system
        :return: The modified path, if any rules applied
        """
        path = path.lower()
        if not arch:
            arch = self._determine_arch(path)

        # Order here matters
        rules: List[Dict[str, str]] = []
        rules.append({
            'pattern': self.SYSTEM_ROOT + self.ARCH_SPECIFIC_DEFAULTS[arch]["szSys86"],
            'replacement': '?sys32'
        })
        if arch == self.X86_64:
            rules.append({
                'pattern': self.SYSTEM_ROOT + self.ARCH_SPECIFIC_DEFAULTS[arch]["szSys64"],
                'replacement': '?sys64'
            })
        rules.append({
            'pattern': self.SYSTEM_DRIVE + self.ARCH_SPECIFIC_DEFAULTS[arch]["szProgFiles86"],
            'replacement': '?pf86'
        })
        if arch == self.X86_64:
            rules.append({
                'pattern': self.SYSTEM_DRIVE + self.ARCH_SPECIFIC_DEFAULTS[arch]["szProgFiles64"],
                'replacement': '?pf64'
            })
        rules.append({
            'regex': f"{self.SYSTEM_DRIVE}{self.SZ_USR_TEMP_PATH}",
            'replacement': '?usrtmp\\\\'
        })
        rules.append({
            'regex': f"{self.SYSTEM_DRIVE}{self.SZ_USR_PATH}",
            'replacement': '?usr\\\\'
        })
        rules.append({
            'pattern': self.SYSTEM_ROOT,
            'replacement': '?win\\'
        })
        rules.append({
            'pattern': self.SYSTEM_DRIVE,
            'replacement': '?c\\'
        })
        for rule in rules:
            if 'pattern' in rule:
                path = self._pattern_substitution(path, rule)
            if 'regex' in rule:
                path = self._regex_substitution(path, rule)
        return path

    def normalize_paths(self, attributes: List[str]):
        """
        This method checks if the provided attributes are part of the Event object, and if so,
        normalizes the path of the given attribute of the object
        :param attributes: A list of attributes that will be checked and normalized
        """
        for attribute in attributes:
            if hasattr(self, attribute):
                setattr(self, attribute, self._normalize_path(getattr(self, attribute)))
            else:
                raise ValueError(f"{self.__class__} does not have attribute '{attribute}'")


class ProcessEvent(Event):
    """
    This class represents a process event on an operating system, and includes key details for that process
    """

    def __init__(self, pid: int = None, ppid: int = None, image: str = None, command_line: str = None,
                 timestamp: float = None, guid: str = None, pguid: str = None):
        """
        This method initializes an ProcessEvent object
        :param pid: The process ID associated with the event
        :param ppid: The process ID of the parent process associated with the event
        :param image: The name of the executable file associated with the event
        :param command_line: The command line used to spawn this process
        :param timestamp: The time at which the event occurred
        :param guid: The unique identifier for the event
        :param pguid: The unique identifier for the parent process that spawned this event
        :return: None
        """
        super().__init__(pid=pid, image=image, timestamp=timestamp, guid=guid, pguid=pguid)
        self.ppid = ppid
        self.command_line = command_line

    @staticmethod
    def keys() -> Set[str]:
        """
        This method returns the class attributes / keys of the dictionary representation of the process event object
        :return: The class attributes / keys of the dictionary representation of the process event object
        """
        return Event.keys().union({"ppid", "command_line"})


class NetworkEvent(Event):
    """
    This class represents a network event on an operating system, and includes key details for that network event
    """

    def __init__(self, protocol: str = None, src_ip: str = None, src_port: int = None, domain: str = None,
                 dest_ip: str = None, dest_port: int = None, pid: int = None, image: str = None,
                 timestamp: float = None, guid: str = None, pguid: str = None):
        """
        This method initializes an ProcessEvent object
        :param protocol: The protocol on the network call (ex. TCP, DNS, UDP, SMTP, etc.)
        :param src_ip: The source IP of the network call
        :param src_port: The source port of the network call
        :param domain: The domain, if any, of the network call
        :param dest_ip: The destination IP of the network call
        :param dest_port: The detination port of the network call
        :param pid: The unique identifier for the parent process that spawned this event
        :param image: The name of the executable file associated with the event
        :param timestamp: The time at which the event occurred
        :param guid: The unique identifier for the event
        :param pguid: The unique identifier for the parent process that spawned this event
        :return: None
        """
        super().__init__(pid=pid, image=image, timestamp=timestamp, guid=guid, pguid=pguid)
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.domain = domain
        self.dest_ip = dest_ip
        self.dest_port = dest_port

    @staticmethod
    def keys() -> Set[str]:
        """
        This method returns the class attributes / keys of the dictionary representation of the network event object
        :return: The class attributes / keys of the dictionary representation of the network event object
        """
        return Event.keys().union({"protocol", "src_ip", "src_port", "domain", "dest_ip", "dest_port"})


class Events:
    """
    This class represents a list of Event objects, and provides validation for data input
    """

    def __init__(self, events: List[Dict[str, Any]] = None, normalize_paths: bool = False):
        """
        This method takes a list of unvalidated events and performs basic validation and logical checks to prepare the
        data for future use
        :param events: A list of unvalidated events
        :param normalize_paths: A flag used to indicate if the paths should be normalized or not
        """
        self.normalize_paths = normalize_paths
        if events is None:
            self.events: List[Event] = []
            self.event_dicts: Dict[str, Any] = {}
            self.sorted_events: List[Any] = []
            self.process_events: List[ProcessEvent] = []
            self.process_event_dicts: Dict[str, Any] = {}
            self.network_events: List[NetworkEvent] = []
            self.network_event_dicts: Dict[str, Any] = {}
        else:
            self.events = self._validate_events(events)
            self.sorted_events = self._sort_things_by_timestamp(self.events)
            self.process_events = self._get_process_events(self.sorted_events, self.normalize_paths)
            self.process_event_dicts = self._convert_events_to_dict(self.process_events)
            self.network_events = self._get_network_events(self.sorted_events)
            self.network_event_dicts = self._convert_events_to_dict(self.network_events)
            self.event_dicts = self._convert_events_to_dict(self.process_events + self.network_events)

    @staticmethod
    def _validate_events(events: List[Dict[str, Any]] = None) -> List[Event]:
        """
        This method validates unvalidated event data
        :param events: A list of unvalidated events
        :return: A list of validated events
        """
        validated_events = []
        process_event_keys = ProcessEvent.keys()
        network_event_keys = NetworkEvent.keys()
        for event in events:
            event_keys = set(event.keys())
            event_keys.add("signatures")
            event_keys.add("tree_id")
            event_keys.add("children")
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
                    pguid=event["pguid"],
                )
                validated_events.append(validated_network_event)
            else:
                raise ValueError(f"The event {event} does not match the process_event format {process_event_keys}"
                                 f" or the network_event format {network_event_keys}.")
        return validated_events

    @staticmethod
    def _get_process_events(events: List[Event] = None, normalize_paths: bool = False) -> List[ProcessEvent]:
        """
        This method returns all events that are process events
        :param events: A list of validated events
        :param normalize_paths: A flag used to indicate if the paths should be normalized or not
        :return: A list of validated process events
        """
        process_events = []
        for event in events:
            if isinstance(event, ProcessEvent):
                if normalize_paths:
                    event.normalize_paths(["image"])
                process_events.append(event)
        return process_events

    @staticmethod
    def _get_network_events(events: List[Event] = None) -> List[NetworkEvent]:
        """
        This method returns all events that are network events
        :param events: A list of validated events
        :return: A list of validated network events
        """
        network_events = []
        for event in events:
            if isinstance(event, NetworkEvent):
                network_events.append(event)
        return network_events

    @staticmethod
    def _sort_things_by_timestamp(things_to_sort_by_timestamp: List[Any] = None) -> List[Any]:
        """
        This method sorts a list of things by their timestamps
        :param things_to_sort_by_timestamp: A list of things to sort by timestamp
        :return: A list of things that have been sorted by timestamp
        """
        if not things_to_sort_by_timestamp:
            return []
        if isinstance(things_to_sort_by_timestamp[0], Dict):
            def timestamp(x): return x["timestamp"]
        else:
            def timestamp(x): return x.timestamp
        sorted_things = sorted(things_to_sort_by_timestamp, key=timestamp)
        return sorted_things

    @staticmethod
    def _convert_events_to_dict(events: List[Event]) -> Dict[str, Any]:
        """
        This method converts events to dictionaries
        :param events: A list of validated event objects
        :return: A dictionary representing the event objects
        """
        events_dict = {}
        mapping_value = "pid"
        if all([event.guid is not None for event in events]):
            mapping_value = "guid"
        for event in events:
            events_dict[getattr(event, mapping_value)] = event.convert_event_to_dict()
        return events_dict


class Artifact:
    """
    This class is used for representing artifacts found in sandboxes
    """

    def __init__(self, name: str = None, path: str = None, description: str = None, to_be_extracted: bool = None):
        """
        This method initializes an artifact object
        :param name: The name of the artifact
        :param path: The path of the artifact
        :param description: The description of the artifact
        :param to_be_extracted: A flag indicating if the artifact should be extracted or added as a supplementary file
        """
        if any(item is None for item in [name, path, description, to_be_extracted]):
            raise Exception("Missing positional arguments for Artifact validation")

        self.name = name
        self.path = path
        self.description = description
        self.to_be_extracted = to_be_extracted


class Signature:
    """
    This class is used for representing a signature that can be linked to a process event
    """

    def __init__(self, pid: int = None, name: str = None, score: int = None):
        """
        This method initializes a signature object
        :param pid: The process ID of the process that this signature is associated with
        :param name: The name of the signature
        :param score: The score of the signature, used for indicating severity
        """
        self.pid = pid
        self.name = name
        self.score = score

    @staticmethod
    def keys() -> Set[str]:
        """
        This method returns the class attributes / keys of the dictionary representation of the signature object
        :return: The class attributes / keys of the dictionary representation of the signature object
        """
        return {"name", "pid", "score"}

    def convert_signature_to_dict(self) -> Dict:
        """
        This method returns the dictionary representation of the event object
        :return: The dictionary representation of the event object
        """
        return self.__dict__


class Signatures:
    """
    This class represents a list of signature objects
    """

    def __init__(self, signatures: List[Dict[str, Any]] = None) -> None:
        """
        This method initializes a list of validated signatures
        :param signatures:
        :return: None
        """
        if signatures is None:
            signatures = []
        self.signatures = self._validate_signatures(signatures)
        self.signature_dicts = self._convert_signatures_to_dicts()

    @staticmethod
    def _validate_signatures(signatures: List[Dict[str, Any]] = None) -> List[Signature]:
        """
        This method validates a list of unvalidated signatures
        :param signatures: A list of unvalidated signatures
        :return: A list of validated signatures
        """
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
        """
        This method converts each validated signature object into a dictionary
        :return: A list of validated signatures represented by dictionaries
        """
        signature_dicts = []
        for signature in self.signatures:
            signature_dict = signature.convert_signature_to_dict()
            signature_dicts.append(signature_dict)
        return signature_dicts


class SandboxOntology(Events):
    """
    This class represents the sandbox ontology and provides key methods used for manipulating data into useful
    structures
    """

    def __init__(self, events: List[Dict[str, Any]] = None, normalize_paths: bool = False) -> None:
        """
        This method initializes the SandboxOntology class by validating a list of unvalidated events
        :param events: A list of unvalidated events
        :param normalize_paths: A flag used to indicate if the paths should be normalized or not
        :return: None
        """
        Events.__init__(self, events=events, normalize_paths=normalize_paths)

    @staticmethod
    def _convert_events_dict_to_tree(events_dict: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        This method converts a dictionary representing events into a tree by using pid/ppid or guid/pguid
        pairs for linking
        :param events_dict: A dictionary of events
        :return: A list of event tree roots, each which their respective branches and leaves
        """
        root = {
            "children": [],
        }
        sorted_events = SandboxOntology._sort_things_by_timestamp(list(events_dict.values()))
        events_seen = []
        key_to_use_for_linking = "ppid"
        key_to_use_for_tracking = "pid"
        if all([any(event_dict.get(key) for key in ["pguid", "guid"]) for event_dict in events_dict.values()]):
            key_to_use_for_linking = "pguid"
            key_to_use_for_tracking = "guid"

        for e in sorted_events:
            # NOTE: not going to delete the original of the duplicated keys, as they may be useful in the future
            if "children" not in e:
                e["children"] = []
            if e[key_to_use_for_linking] in events_seen:
                events_dict[e[key_to_use_for_linking]]["children"].append(e)
            else:
                root["children"].append(e)

            events_seen.append(e[key_to_use_for_tracking])

        return SandboxOntology._sort_things_by_timestamp(root["children"])

    @staticmethod
    def _validate_artifacts(artifact_list: List[Dict[str, Any]] = None) -> List[Artifact]:
        """
        This method validates a list of unvalidated artifacts
        :param artifact_list: A list of unvalidated artifacts
        :return: A list of validated artifacts
        """
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
    def _handle_artifact(artifact: Artifact = None, artifacts_result_section: ResultSection = None) -> None:
        """
        This method handles a single artifact and creates a ResultSection for the artifact, if appropriate
        :param artifact: An artifact object
        :param artifacts_result_section: A master ResultSection that will contain the ResultSection created for the
        given artifact
        :return: None
        """
        if artifact is None:
            raise Exception("Artifact cannot be None")

        artifact_result_section = None
        for regex in [HOLLOWSHUNTER_EXE_REGEX, HOLLOWSHUNTER_DLL_REGEX]:
            pattern = compile(regex)
            if pattern.match(artifact.name):
                artifact_result_section = next(
                    (subsection for subsection in artifacts_result_section.subsections
                     if subsection.title_text == HOLLOWSHUNTER_TITLE),
                    None)
                if artifact_result_section is None:
                    artifact_result_section = ResultSection(HOLLOWSHUNTER_TITLE)
                    artifact_result_section.set_heuristic(17)
                    artifact_result_section.add_line("HollowsHunter dumped the following:")
                artifact_result_section.add_line(f"\t- {artifact.name}")
                artifact_result_section.add_tag("dynamic.process.file_name", artifact.name)
                # As of right now, heuristic ID 17 is associated with the Injection category in the Cuckoo service
                if regex in [HOLLOWSHUNTER_EXE_REGEX]:
                    artifact_result_section.heuristic.add_signature_id("hollowshunter_exe")
                elif regex in [HOLLOWSHUNTER_DLL_REGEX]:
                    artifact_result_section.heuristic.add_signature_id("hollowshunter_dll")

        if artifact_result_section is not None:
            artifacts_result_section.add_subsection(artifact_result_section)

    def _match_signatures_to_events(self, events: Dict[str, Any],
                                    signature_dicts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        This method matches signatures to events
        :param events: A dictionary containing validated events
        :param signature_dicts: A list of signatures to be matched to validated events
        :return: A dictionary containing validated events that have signatures associated with them
        """
        event_dicts_with_signatures = {}
        copy_of_event_dicts = events.copy()
        for key, event_dict in copy_of_event_dicts.items():
            event_dicts_with_signatures[key] = event_dict

        pids = [event_dict["pid"] for event_dict in copy_of_event_dicts.values()]
        for signature_dict in signature_dicts:
            pid = signature_dict["pid"]
            name = signature_dict["name"]
            score = signature_dict["score"]
            if pid not in pids:
                # Ignore it
                log.warning(f"{signature_dict} does not match up with a PID in "
                            f"{event_dicts_with_signatures.keys()}")
            else:
                # We should always get a key from this
                key = next(key for key, event_dict in event_dicts_with_signatures.items()
                           if event_dict["pid"] == pid)
                event_dicts_with_signatures[key]["signatures"][name] = score

        return event_dicts_with_signatures

    def get_event_tree(self, signatures: List[Dict[str, Any]] = None, tree_type: str = PROCESS, safelist: List[str] = None) -> List[Dict[str, Any]]:
        """
        This method generates the event tree
        :param signatures: A list of unvalidated signatures
        :param tree_type: The type of tree that is to be generated
        :param safelist: A safelist of tree IDs that is to be applied to the events
        :return: The event tree
        """
        if signatures is None:
            signatures = []
        s = Signatures(signatures=signatures)

        if tree_type == PROCESS:
            events = self.process_event_dicts
        elif tree_type == EVENT:
            events = self.event_dicts
        else:
            raise ValueError(f"Tree type {tree_type} is not one of [{PROCESS}, {EVENT}]")

        if signatures:
            events = self._match_signatures_to_events(events, s.signature_dicts)

        tree = self._convert_events_dict_to_tree(events)

        SandboxOntology._create_tree_ids(tree)
        if safelist:
            tree = SandboxOntology._filter_event_tree_against_safe_tree_ids(tree, safelist)
        return tree

    def get_event_tree_result_section(self, signatures: List[Dict[str, Any]] = None, tree_type: str = PROCESS,
                                      safelist: List[str] = None) -> ResultProcessTreeSection:
        """
        This method creates the Typed ResultSection for Process (Event) Trees
        :param signatures: A list of unvalidated signatures
        :param tree_type: The type of tree that is to be generated
        :param safelist: A safelist of tree IDs that is to be applied to the events
        :return: The Typed ResultSection for the Process (Event) Tree
        """
        tree = self.get_event_tree(signatures, tree_type, safelist)
        items: List[ProcessItem] = []
        for event in tree:
            SandboxOntology._convert_event_tree_to_result_section(items, event)
        process_tree_result_section = ResultProcessTreeSection("Spawned Process Tree")
        for item in items:
            process_tree_result_section.add_process(item)
        return process_tree_result_section

    @staticmethod
    def _convert_event_tree_to_result_section(items: List[ProcessItem], event: ProcessEvent,
                                              parent: Optional[ProcessItem] = None) -> None:
        """
        This method converts the event tree into a ResultSection using recursion
        :param items: A list of ProcessItem objects
        :param event: The ProcessEvent to be converted
        :param parent: The ProcessItem of the event to be converted
        :return: None
        """
        process_keys_to_match = ProcessEvent.keys()
        network_keys_to_match = NetworkEvent.keys()
        process_keys_to_match.add("tree_id")
        network_keys_to_match.add("tree_id")
        if event.keys() != process_keys_to_match:
            raise ValueError(f"{event} is not a Process Event because it has !")

        e = ProcessItem(
            pid=event["pid"],
            name=event["image"],
            cmd=event["command_line"],
        )

        for name, score in event["signatures"].items():
            e.add_signature(name, score)

        for child in event["children"][:]:
            if set(child.keys()) == network_keys_to_match:
                c = NetworkItem(
                    pid=child["pid"],
                    name=child["image"],
                    protocol=child["protocol"],
                    dest_ip=child["dest_ip"],
                    dest_port=child["dest_port"],
                    domain=child["domain"],
                )
                for name, score in child["signatures"].items():
                    c.add_signature(name, score)

                e.add_network_event(c)
            elif child.keys() == process_keys_to_match:
                SandboxOntology._convert_event_tree_to_result_section(items, child, e)
            event["children"].remove(child)

        if not event["children"] and not parent:
            items.append(e)
        elif not event["children"] and parent:
            parent.add_child_process(e)

    @staticmethod
    def _create_hashed_node(parent: str, node: Dict[str, Any], tree_ids: List[str]) -> None:
        """
        This method takes a single node and hashes node attributes.
        Recurses through children to do the same.
        :param parent: A string representing the tree id
        :param node: A dictionary representing the node to hash
        :param tree_ids: A list containing the tree IDs from the root
        :return: None
        """
        children = node["children"]
        value_to_create_hash_from = (parent + node["image"]).encode()
        sha256sum = sha256(value_to_create_hash_from).hexdigest()
        node['tree_id'] = sha256sum

        if not children:
            tree_ids.append(sha256sum)

        for child in children:
            SandboxOntology._create_hashed_node(sha256sum, child, tree_ids)

    @staticmethod
    def _create_tree_ids(process_tree: List[Dict[str, Any]]) -> List[List[str]]:
        """
        This method creates tree IDs for each node in the process tree
        :param process_tree: A list of dictionaries where each dictionary represents a root.
        :return: A list of list of strings representing the tree_ids for all of the root-to-leaf paths
                 in the same order as the provided process tree
        """
        # List that holds the tree IDs of each root in a tree
        process_tree_ids = []

        for root in process_tree:
            # List to hold each hash computed using the _create_hashed_node function
            tree_ids = []
            SandboxOntology._create_hashed_node("", root, tree_ids)
            process_tree_ids.append(tree_ids)

        return process_tree_ids

    @staticmethod
    def _remove_safe_leaves_helper(node: Dict[str, Any], safe_tree_ids: List[str]) -> Union[str, None]:
        """
        This method is used to recursively remove safe branches from the given node. It removes a branch from the leaf
        up until it is reaches a node that is not safelisted
        :param node: A dictionary of a process tree node (root)
        :param safe_tree_ids: All of the safe leaf tree IDs (the safelist)
        :return: Returns the string representing the node's hash for the purpose of recursive removal,
                 or returns None if the removal is complete
        """
        children: List[Dict[str, Any]] = node['children']
        num_removed = 0
        for index, _ in enumerate(children):
            child_to_operate_on = children[index - num_removed]
            hash_to_remove = SandboxOntology._remove_safe_leaves_helper(child_to_operate_on, safe_tree_ids)
            if hash_to_remove and hash_to_remove == child_to_operate_on['tree_id']:
                children.remove(child_to_operate_on)
                num_removed += 1
                # We need to overwrite the hash of the parent node with the hash to remove to that it will be
                # removed from the tree as well.
                if not children:
                    node["tree_id"] = hash_to_remove

        if not children:
            tree_id = node['tree_id']
            if tree_id in safe_tree_ids:
                return tree_id
            else:
                return None

    @staticmethod
    def _remove_safe_leaves(process_tree: List[Dict[str, Any]], safe_tree_ids: List[str]) -> None:
        """
        This method checks each leaf's hash against the safe tree IDs and removes safe branches from the process tree
        :param process_tree: A list of dictionaries where each dictionary represents a root.
        :param safe_tree_ids: A list containing the tree IDs of each safe branch
        :return: None
        """
        for root in process_tree[:]:
            _ = SandboxOntology._remove_safe_leaves_helper(root, safe_tree_ids)
            if root['tree_id'] in safe_tree_ids and not root["children"]:
                process_tree.remove(root)

    @staticmethod
    def _filter_event_tree_against_safe_tree_ids(event_tree: List[Dict[str, Any]], safe_tree_ids: List[str]) \
            -> List[Dict[str, Any]]:
        """
        This method takes an event tree and a list of safe process tree tree IDs, and filters out safe process roots
        in the tree.
        :param event_tree: A list of processes in a tree structure
        :param safe_tree_ids: A List of tree IDs representing safe leaf nodes/branches
        :return: A list of processes in a tree structure, with the safe branches filtered out
        """
        SandboxOntology._remove_safe_leaves(event_tree, safe_tree_ids)
        return event_tree

    def get_events(self) -> List[Dict[str, Any]]:
        """
        This method returns a list of dictionaries each representing an event, sorted according to timestamp
        :return: The list of sorted dictionaries
        """
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
    def handle_artifacts(
            artifact_list: List[Dict[str, Any]],
            request: ServiceRequest, collapsed: bool = False) -> ResultSection:
        """
        Goes through each artifact in artifact_list, uploading them and adding result sections accordingly
        :param artifact_list: List of dictionaries that each represent an artifact
        :param collapsed: A flag used for indicating if the Sandbox Artifacts ResultSection should be collapsed or not
        :return: A ResultSection containing any Artifact ResultSections
        """

        validated_artifacts = SandboxOntology._validate_artifacts(artifact_list)

        artifacts_result_section = ResultSection("Sandbox Artifacts", auto_collapse=collapsed)

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
