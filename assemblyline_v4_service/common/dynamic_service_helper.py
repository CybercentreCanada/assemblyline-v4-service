from typing import Dict, List, Optional, Any, Union
from re import compile, escape, sub
from logging import getLogger
from assemblyline.common import log as al_log
from assemblyline_v4_service.common.result import ResultSection
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import MaxExtractedExceeded
from hashlib import sha256

HOLLOWSHUNTER_EXE_REGEX = r"[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*(\.*[a-zA-Z0-9]+)+\.exe$"
HOLLOWSHUNTER_SHC_REGEX = r"[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*(\.*[a-zA-Z0-9]+)+\.shc$"
HOLLOWSHUNTER_DLL_REGEX = r"[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*(\.*[a-zA-Z0-9]+)+\.dll$"

HOLLOWSHUNTER_TITLE = "HollowsHunter Injected Portable Executable"

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
                raise ValueError(f"The event {event} does not match the process_event format {process_event_keys}"
                                 f" or the network_event format {network_event_keys}.")
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
            def timestamp(x): return x["timestamp"]
        else:
            def timestamp(x): return x.timestamp
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
                log.warning(f"{signature_dict} does not match up with a PID in "
                            f"{process_event_dicts_with_signatures.keys()}")
            else:
                # We should always get a key from this
                key = next(key for key, process_event_dict in process_event_dicts_with_signatures.items()
                           if process_event_dict["pid"] == pid)
                process_event_dicts_with_signatures[key]["signatures"][name] = score

        return process_event_dicts_with_signatures

    def get_process_tree(self, safelist: List[str] = None) -> List[Dict[str, Any]]:
        process_tree = self._convert_processes_dict_to_tree(self.process_event_dicts)
        SandboxOntology._create_tree_ids(process_tree)
        if safelist:
            process_tree = SandboxOntology._filter_process_tree_against_safe_tree_ids(process_tree, safelist)
        return process_tree

    def get_process_tree_with_signatures(self, signatures: List[Dict[str, Any]] = None, safelist: List[str] = None) \
            -> List[Dict[str, Any]]:
        if signatures is None:
            signatures = []
        s = Signatures(signatures=signatures)
        process_event_dicts_with_signatures = self._match_signatures_to_process_events(s.signature_dicts)
        process_tree_with_signatures = self._convert_processes_dict_to_tree(process_event_dicts_with_signatures)
        SandboxOntology._create_tree_ids(process_tree_with_signatures)
        if safelist:
            process_tree_with_signatures = \
                SandboxOntology._filter_process_tree_against_safe_tree_ids(process_tree_with_signatures, safelist)
        return process_tree_with_signatures

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
    def _filter_process_tree_against_safe_tree_ids(process_tree: List[Dict[str, Any]], safe_tree_ids: List[str]) \
            -> List[Dict[str, Any]]:
        """
        This method takes a process tree and a list of safe process tree tree IDs, and filters out safe process roots
        in the tree.
        :param process_tree: A list of processes in a tree structure
        :param safe_tree_ids: A List of tree IDs representing safe leaf nodes/branches
        :return: A list of processes in a tree structure, with the safe branches filtered out
        """
        SandboxOntology._remove_safe_leaves(process_tree, safe_tree_ids)
        return process_tree

    def get_events(self) -> List[Dict]:
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
