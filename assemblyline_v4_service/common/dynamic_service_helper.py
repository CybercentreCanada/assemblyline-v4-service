from typing import List
from re import compile
from assemblyline_v4_service.common.result import ResultSection
from assemblyline_v4_service.common.request import ServiceRequest

HOLLOWSHUNTER_EXE_REGEX = "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.exe$"
HOLLOWSHUNTER_SHC_REGEX = "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.shc$"
HOLLOWSHUNTER_DLL_REGEX = "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.dll$"


class Process:
    def __init__(self, pid: int = None, ppid: int = None, image: str = None, command_line: str = None, timestamp: float = None):
        self.pid = pid  # Same as ProcessID
        self.ppid = ppid  # Same as ParentProcessID
        self.image = image  # Same as Process Name
        self.command_line = command_line
        self.timestamp = timestamp  # Do we need this?  Also the equivalent of first_seen

    def convert_process_to_dict(self):
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "image": self.image,
            "command_line": self.command_line,
            "timestamp": self.timestamp
        }


class Artefact:
    def __init__(self, name: str = None, path: str = None, description: str = None, to_be_extracted: bool = None):
        if any(item is None for item in [name, path, description, to_be_extracted]):
            raise Exception("Missing positional arguments for Artefact validation")

        self.name = name
        self.path = path
        self.description = description
        self.to_be_extracted = to_be_extracted


class Ontology:
    def __init__(self, process_list: list = None):
        if process_list is None:
            self.process_list = []
        else:
            self.process_list = self._validate_process_list(process_list)

    @staticmethod
    def _validate_process_list(process_list) -> List[Process]:
        valid_process_list = []
        for process in process_list:
            valid_process = Process(
                pid=process["pid"],
                ppid=process["ppid"],
                image=process["image"],
                command_line=process["command_line"],
                timestamp=process["timestamp"],
            )
            valid_process_list.append(valid_process)
        return valid_process_list

    def _convert_processes_to_dict(self) -> dict:
        processes_dict = {}
        for process in self.process_list:
            processes_dict[process.pid] = process.convert_process_to_dict()
        return processes_dict

    @staticmethod
    def _convert_processes_dict_to_tree(processes_dict: dict = None) -> List[dict]:
        root = {
            "children": [],
        }
        sorted_processes = Ontology._sort_things_by_timestamp(list(processes_dict.values()))
        procs_seen = []

        for p in sorted_processes:
            p["children"] = []
            if p["ppid"] in procs_seen:
                processes_dict[p["ppid"]]["children"].append(p)
            else:
                root["children"].append(p)

            procs_seen.append(p["pid"])

        return Ontology._sort_things_by_timestamp(root["children"])

    @staticmethod
    def _sort_things_by_timestamp(things_to_sort_by_timestamp: List[dict] = None) -> List[dict]:
        timestamp = lambda x: x["timestamp"]
        sorted_things = sorted(things_to_sort_by_timestamp, key=timestamp)
        return sorted_things

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
    def _handle_artefact(artefact: Artefact = None, artefacts_result_section: ResultSection = None) -> ResultSection:
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

        if artefact_result_section is not None:
            artefacts_result_section.add_subsection(artefact_result_section)

    def get_process_tree(self) -> List[dict]:
        processes_dict = self._convert_processes_to_dict()
        process_tree = self._convert_processes_dict_to_tree(processes_dict)
        return process_tree

    @staticmethod
    def get_events(process_list: List[dict] = None, network_calls: List[dict] = None) -> List[dict]:
        if process_list is None:
            process_list = []
        if network_calls is None:
            network_calls = []

        events = process_list + network_calls
        sorted_events = Ontology._sort_things_by_timestamp(events)
        return sorted_events

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

        validated_artefacts = Ontology._validate_artefacts(artefact_list)

        artefacts_result_section = ResultSection("Sandbox Artefacts")

        for artefact in validated_artefacts:
            Ontology._handle_artefact(artefact, artefacts_result_section)

            if artefact.to_be_extracted:
                request.add_extracted(artefact.path, artefact.name, artefact.description)
            else:
                request.add_supplementary(artefact.path, artefact.name, artefact.description)

        return artefacts_result_section if artefacts_result_section.subsections else None
