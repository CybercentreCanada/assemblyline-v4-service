from hashlib import sha256
from json import dumps
from logging import getLogger
from re import compile, escape, sub, findall
from typing import Any, Dict, List, Optional, Set, Union
from uuid import UUID, uuid4

from assemblyline.common import log as al_log
from assemblyline.common.attack_map import (
    attack_map,
    software_map,
    group_map,
    revoke_map,
)
from assemblyline.odm.base import DOMAIN_REGEX, IP_REGEX, URI_PATH

# from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    ResultSection,
    ProcessItem,
    ResultProcessTreeSection,
    ResultTableSection,
    TableRow
)
from assemblyline_v4_service.common.safelist_helper import URL_REGEX
from assemblyline_v4_service.common.tag_helper import add_tag
from assemblyline_v4_service.common.task import MaxExtractedExceeded

al_log.init_logging("service.service_base.dynamic_service_helper")
log = getLogger("assemblyline.service.service_base.dynamic_service_helper")

X86_64 = "x86_64"
X86 = "x86"

SYSTEM_DRIVE = "c:\\"
SYSTEM_ROOT = "c:\\windows\\"
SZ_USR_TEMP_PATH = "users\\*\\appdata\\local\\temp\\"
SZ_USR_PATH = "users\\*\\"
ARCH_SPECIFIC_DEFAULTS = {
    X86_64: {
        "szProgFiles86": "program files (x86)",
        "szProgFiles64": "program files",
        "szSys86": "syswow64",
        "szSys64": "system32",
    },
    X86: {"szProgFiles86": "program files", "szSys86": "system32"},
}

HOLLOWSHUNTER_EXE_REGEX = r"[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[0-9a-z]{3,}(\.[a-zA-Z0-9]{2,})*\.exe$"
HOLLOWSHUNTER_DLL_REGEX = r"[0-9]{1,}_hollowshunter\/hh_process_[0-9]{3,}_[0-9a-z]{3,}(\.[a-zA-Z0-9]{2,})*\.dll$"

HOLLOWSHUNTER_TITLE = "HollowsHunter Injected Portable Executable"


def update_object_items(self, update_items: Dict[str, Any]) -> None:
    """
    This method updates the attributes of an object
    :param update_items: A dictionary where the keys are the object attributes to be updated
    :return: None
    """
    if all(value is None for value in update_items.values()):
        return
    for key, value in update_items.items():
        if value is None or value == "":
            continue
        if hasattr(self, key) and getattr(self, key) not in ["", None, [], {}, (), float("inf"), float("-inf")]:
            # DO NOT OVERWRITE DATA (UNLESS ITS EMPTY)
            pass
        elif hasattr(self, key):
            setattr(self, key, value)
        else:
            log.warning(
                f"{self.__class__} does not have the attribute {key}. Ignoring..."
            )


class Artifact:
    """
    This class is used for representing artifacts found in sandboxes
    """

    def __init__(
        self,
        name: str = None,
        path: str = None,
        description: str = None,
        to_be_extracted: bool = None,
    ):
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

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {key: value for key, value in self.__dict__.items()}


class ObjectID:
    def __init__(
        self,
        guid: str = None,
        tag: str = None,
        treeid: str = None,
        processtree: str = None,
        time_observed: float = None,
    ) -> None:
        """
        This method initializes the characteristics used to identify an object
        :param guid: The GUID associated with the process
        :param tag: The tag of the object
        :param treeid: The hash of the tree ID
        :param processtree: Human readable tree ID (concatenation of tags)
        :param time_observed: An EPOCH time representing when the object was first observed
        :return: None
        """
        self.guid: str = f"{{{str(UUID(guid)).upper()}}}" if guid else None
        self.tag: str = tag
        self.treeid: str = treeid
        self.processtree: str = processtree
        self.time_observed: float = time_observed

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {key: value for key, value in self.__dict__.items()}

    def assign_guid(self) -> None:
        """
        This method assigns the GUID for the process object
        :return: None
        """
        self.guid: str = f"{{{str(uuid4()).upper()}}}"

    def set_tag(self, tag: str) -> None:
        """
        This method updates the tag for the ObjectID
        :param tag: The tag of the ObjectID
        :return: None
        """
        if not isinstance(tag, str) or not tag:
            return
        self.tag = tag

    def set_time_observed(self, time_observed: Union[float, int]) -> None:
        """
        This method updates the time_observed for the ObjectID
        :param time_observed: The time_observed of the ObjectID
        :return: None
        """
        if not (isinstance(time_observed, float) or isinstance(time_observed, int)) or not time_observed:
            return
        self.time_observed = float(time_observed)


class Process:
    def __init__(
        self,
        guid: str = None,
        tag: str = None,
        treeid: str = None,
        processtree: str = None,
        pguid: str = None,
        ptag: str = None,
        ptreeid: str = None,
        pprocesstree: str = None,
        pimage: str = None,
        pcommand_line: str = None,
        ppid: int = None,
        pid: int = None,
        image: str = None,
        command_line: str = None,
        start_time: float = None,
        end_time: float = None,
        integrity_level: str = None,
        image_hash: str = None,
        original_file_name: str = None,
        objectid: ObjectID = None,
        pobjectid: ObjectID = None,
    ) -> None:
        """
        This method initializes a process object
        :param guid: The GUID associated with the process
        :param tag: The normalized tag of the object
        :param treeid: The hash of the tree ID
        :param processtree: Human readable tree ID (concatenation of tags)
        :param pguid: The GUID associated with the parent process
        :param ptag: The tag associated with the parent process
        :param ptreeid: The hash of the parent's tree ID
        :param pprocesstree: Human readable tree ID of parent (concatenation of tags)
        :param pimage: The image of the parent process that spawned this process
        :param pcommand_line: The command line that the parent process ran
        :param ppid: The process ID of the parent process
        :param pid: The process ID
        :param image: The image of the process
        :param command_line: The command line that the process ran
        :param start_time: An EPOCH time representing when the process was created
        :param end_time: An EPOCH time representing when the process was terminated
        :param integrity_level: The integrity level of the process
        :param image_hash: The hash of the file run
        :param original_file_name: The original name of the file
        :param objectid: The characteristics used to identify an object
        :param pobjectid: The characteristics used to identify the parent object
        :return: None
        """
        if start_time and end_time and start_time > end_time:
            raise ValueError(
                f"Start time {start_time} cannot be greater than end time {end_time}."
            )
        self.start_time: float = start_time if start_time else None
        self.end_time: float = end_time if end_time else None

        # NOTE if an ObjectID is passed in, the guid, tag and treeid will not be used
        if isinstance(objectid, ObjectID):
            self.objectid: ObjectID = objectid
        else:
            self.objectid: ObjectID = ObjectID(
                guid=guid, tag=tag, treeid=treeid, processtree=processtree, time_observed=self.start_time
            )

        # Parent process details
        # NOTE if an ObjectID is passed in, the pguid, ptag and ptreeid will not be used
        if isinstance(pobjectid, ObjectID):
            self.pobjectid: ObjectID = pobjectid
        else:
            self.pobjectid: ObjectID = ObjectID(guid=pguid, tag=ptag, treeid=ptreeid, processtree=pprocesstree)
        self.pimage: str = pimage
        self.pcommand_line: str = pcommand_line
        self.ppid: int = ppid

        if pid and not isinstance(pid, int):
            raise ValueError(f"{pid} is an invalid pid.")
        self.pid: int = pid

        self.image: str = image
        self.command_line: str = command_line

        # Do not overwrite the given ObjectID tag even if an image is provided
        if isinstance(objectid, ObjectID) and not objectid.tag and self.image:
            self.set_objectid_tag(self.image)
        elif not isinstance(objectid, ObjectID) and self.image:
            self.set_objectid_tag(self.image)

        if isinstance(pobjectid, ObjectID) and not pobjectid.tag and self.pimage:
            self.set_pobjectid_tag(self.pimage)
        elif not isinstance(pobjectid, ObjectID) and self.pimage:
            self.set_pobjectid_tag(self.pimage)

        self.integrity_level: str = (
            integrity_level.lower() if isinstance(integrity_level, str) else None
        )
        self.image_hash: str = image_hash
        self.original_file_name: str = original_file_name

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {
            key: value if not isinstance(value, ObjectID) else value.as_primitives()
            for key, value in self.__dict__.items()
        }

    def update(self, **kwargs) -> None:
        """
        This method updates attributes with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating attributes
        :return: None
        """
        objectid_keys = ["guid", "tag", "treeid", "processtree", "time_observed"]
        pobjectid_keys = ["pguid", "ptag", "ptreeid", "pprocesstree", "ptime_observed"]

        if all(value is None for value in kwargs.values()):
            return

        if "objectid" in kwargs:
            objectid = kwargs.pop("objectid")
            if objectid:
                self.update_objectid(**objectid)
        else:
            objectid_kwargs = {
                key: value for key, value in kwargs.items() if key in objectid_keys
            }
            self.update_objectid(**objectid_kwargs)

            if "tag" not in objectid_kwargs and "image" in kwargs:
                self.set_objectid_tag(kwargs["image"])

        if "pobjectid" in kwargs:
            pobjectid = kwargs.pop("pobjectid")
            if pobjectid:
                self.update_pobjectid(**pobjectid)
        else:
            # Remove the initial p
            pobjectid_kwargs = {
                key[1:]: value for key, value in kwargs.items() if key in pobjectid_keys
            }
            self.update_pobjectid(**pobjectid_kwargs)

            if "tag" not in pobjectid_kwargs and "pimage" in kwargs:
                self.set_pobjectid_tag(kwargs["pimage"])

        if "start_time" in kwargs and self.objectid.time_observed is None:
            self.objectid.set_time_observed(kwargs["start_time"])

        if "integrity_level" in kwargs and isinstance(kwargs["integrity_level"], str):
            kwargs["integrity_level"] = kwargs["integrity_level"].lower()

        # Remove objectid attributes
        kwargs = {
            key: value
            for key, value in kwargs.items()
            if key not in objectid_keys and key not in pobjectid_keys
        }
        update_object_items(self, kwargs)

    def set_parent(self, parent: object) -> None:
        """
        This method sets the parent details for the process
        :param parent: The Process object for the parent process
        :return: None
        """
        if parent is None or parent == self:
            return
        self.pobjectid = parent.objectid
        self.pimage: str = parent.image
        if self.pcommand_line is None:
            self.pcommand_line: str = parent.command_line
        self.ppid: int = parent.pid

    def set_start_time(self, start_time: float) -> None:
        """
        This method updates the start time for the Process
        :param start_time: The start time of the Process
        :return: None
        """
        self.start_time = start_time

    def set_end_time(self, end_time: float) -> None:
        """
        This method updates the end time for the Process
        :param end_time: The end time of the Process
        :return: None
        """
        self.end_time = end_time

    def is_guid_a_match(self, guid: str) -> bool:
        """
        This method confirms if a given GUID matches the Process object's GUID
        :param guid: The GUID to requested to confirm a match
        :return: A boolean flag representing if the GUID matched
        """
        try:
            return self.objectid.guid == f"{{{str(UUID(guid)).upper()}}}"
        except ValueError:
            return False

    def set_objectid_tag(self, image: Optional[str]) -> None:
        """
        This method normalizes the image path and sets the objectid tag
        :return: None
        """
        if not image:
            return
        self.objectid.set_tag(Process._normalize_path(image))

    def set_pobjectid_tag(self, image: Optional[str]) -> None:
        """
        This method normalizes the image path and sets the pobjectid tag
        :return: None
        """
        if not image:
            return
        self.pobjectid.set_tag(Process._normalize_path(image))

    def update_objectid(self, **kwargs) -> None:
        """
        This method updates the process objectid attributes with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the process objectid attributes
        :return: None
        """
        if all(value is None for value in kwargs.values()):
            return
        if not self.objectid:
            self.objectid: ObjectID = ObjectID()

        if kwargs.get("guid"):
            try:
                kwargs["guid"] = f"{{{str(UUID(kwargs['guid'])).upper()}}}"
            except ValueError:
                log.warning(f"Invalid GUID '{kwargs.pop('guid')}'")

        update_object_items(self.objectid, kwargs)

    def update_pobjectid(self, **kwargs) -> None:
        """
        This method updates the process pobjectid attributes with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the process pobjectid attributes
        :return: None
        """
        if all(value is None for value in kwargs.values()):
            return
        if not self.pobjectid:
            self.pobjectid: ObjectID = ObjectID()

        if kwargs.get("guid"):
            try:
                kwargs["guid"] = f"{{{str(UUID(kwargs['guid'])).upper()}}}"
            except ValueError:
                log.warning(f"Invalid GUID {kwargs.pop('guid')}")

        update_object_items(self.pobjectid, kwargs)

    @staticmethod
    def _determine_arch(path: str) -> str:
        """
        This method determines what architecture the operating system was built with where the event took place
        :param path: The file path of the image associated with an event
        :return: The architecture of the operating system
        """
        # Clear indicators in a file path of the architecture of the operating system
        if any(item in path for item in ["program files (x86)", "syswow64"]):
            return X86_64
        return X86

    @staticmethod
    def _pattern_substitution(path: str, rule: Dict[str, str]) -> str:
        """
        This method applies pattern rules for explicit string substitution
        :param path: The file path of the image associated with an event
        :param rule: The rule to be applied, containing a pattern and the replacement value
        :return: The modified path, if any rules applied
        """
        if path.startswith(rule["pattern"]):
            path = path.replace(rule["pattern"], rule["replacement"])
        return path

    @staticmethod
    def _regex_substitution(path: str, rule: Dict[str, str]) -> str:
        """
        This method applies a regular expression for implicit string substitution
        :param path: The file path of the image associated with an event
        :param rule: The rule to be applied, containing a pattern and the replacement value
        :return: The modified path, if any rules applied
        """
        rule["regex"] = rule["regex"].split("*")
        rule["regex"] = [escape(e) for e in rule["regex"]]
        rule["regex"] = "[^\\\\]+".join(rule["regex"])
        path = sub(rf"{rule['regex']}", rule["replacement"], path)
        return path

    @staticmethod
    def _normalize_path(path: str, arch: Optional[str] = None) -> str:
        """
        This method determines what rules should be applied based on architecture and the applies the rules to the path
        :param path: The file path of the image associated with an event
        :param arch: The architecture of the operating system
        :return: The modified path, if any rules applied
        """
        path = path.lower()
        if not arch:
            arch = Process._determine_arch(path)

        # Order here matters
        rules: List[Dict[str, str]] = []
        rules.append(
            {
                "pattern": SYSTEM_ROOT + ARCH_SPECIFIC_DEFAULTS[arch]["szSys86"],
                "replacement": "?sys32",
            }
        )
        if arch == X86_64:
            rules.append(
                {
                    "pattern": SYSTEM_ROOT + ARCH_SPECIFIC_DEFAULTS[arch]["szSys64"],
                    "replacement": "?sys64",
                }
            )
        rules.append(
            {
                "pattern": SYSTEM_DRIVE + ARCH_SPECIFIC_DEFAULTS[arch]["szProgFiles86"],
                "replacement": "?pf86",
            }
        )
        if arch == X86_64:
            rules.append(
                {
                    "pattern": SYSTEM_DRIVE
                    + ARCH_SPECIFIC_DEFAULTS[arch]["szProgFiles64"],
                    "replacement": "?pf64",
                }
            )
        rules.append(
            {"regex": f"{SYSTEM_DRIVE}{SZ_USR_TEMP_PATH}", "replacement": "?usrtmp\\\\"}
        )
        rules.append(
            {"regex": f"{SYSTEM_DRIVE}{SZ_USR_PATH}", "replacement": "?usr\\\\"}
        )
        rules.append({"pattern": SYSTEM_ROOT, "replacement": "?win\\"})
        rules.append({"pattern": SYSTEM_DRIVE, "replacement": "?c\\"})
        for rule in rules:
            if "pattern" in rule:
                path = Process._pattern_substitution(path, rule)
            if "regex" in rule:
                path = Process._regex_substitution(path, rule)
        return path


class NetworkConnection:
    OUTBOUND = "outbound"
    INBOUND = "inbound"
    UNKNOWN = "unknown"
    DIRECTIONS = [OUTBOUND, INBOUND, UNKNOWN]
    TCP = "tcp"
    UDP = "udp"
    TRANSPORT_LAYER_PROTOCOL = [TCP, UDP]

    def __init__(
        self,
        guid: str = None,
        tag: str = None,
        treeid: str = None,
        processtree: str = None,
        process: Process = None,
        source_ip: str = None,
        source_port: int = None,
        destination_ip: str = None,
        destination_port: int = None,
        transport_layer_protocol: str = None,
        direction: str = None,
        time_observed: float = None,
        objectid: ObjectID = None,
    ) -> None:
        """
        Details for a low-level network connection by IP
        :param guid: The GUID associated with the network connection
        :param tag: The normalized tag of the object
        :param tree_id: The hash of the tree ID
        :param processtree: Human readable tree ID (concatenation of tags)
        :param process: The process that spawned the network connection
        :param source_ip: The source IP of the connection
        :param source_port: The source port of the connection
        :param destination_ip: The destination IP of the connection
        :param destination_port: The destination IP of the connection
        :param transport_layer_protocol: The transport layer protocol of the connection
        :param direction: The direction of the network connection
        :param time_observed: The time at which the connection was spotted
        :param objectid: The characteristics used to identify an object
        :return: None
        """
        # NOTE if an ObjectID is passed in, the guid, tag and treeid will not be used
        if isinstance(objectid, ObjectID):
            self.objectid: ObjectID = objectid
        else:
            self.objectid: ObjectID = ObjectID(
                guid=guid, tag=tag, treeid=treeid, processtree=processtree, time_observed=time_observed
            )

        if not self.objectid.guid:
            self.objectid.assign_guid()

        if isinstance(process, Process):
            self.process: Process = process
        else:
            self.process = None

        self.source_ip: str = source_ip
        self.source_port: int = source_port
        self.destination_ip: str = destination_ip
        self.destination_port: int = destination_port

        if (
            transport_layer_protocol
            and transport_layer_protocol not in self.TRANSPORT_LAYER_PROTOCOL
        ):
            raise ValueError(
                f"Invalid transport layer protocol: {transport_layer_protocol}"
            )
        self.transport_layer_protocol: str = transport_layer_protocol

        if direction and direction not in self.DIRECTIONS:
            raise ValueError(f"Invalid direction: {direction}")
        self.direction: str = direction

    def update_objectid(self, **kwargs) -> None:
        """
        This method updates the network connection objectid attributes with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the network connection objectid attributes
        :return: None
        """
        if all(value is None for value in kwargs.values()):
            return
        if not self.objectid:
            self.objectid: ObjectID = ObjectID()
        update_object_items(self.objectid, kwargs)

    def update(self, **kwargs) -> None:
        """
        This method updates attributes with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating attributes
        :return: None
        """
        objectid_keys = ["guid", "tag", "treeid", "processtree", "time_observed"]
        if all(value is None for value in kwargs.values()):
            return

        if "objectid" in kwargs:
            objectid = kwargs.pop("objectid")
            if objectid:
                self.update_objectid(**objectid)
        else:
            # Get the objectid attributes out
            objectid_kwargs = {
                key: value for key, value in kwargs.items() if key in objectid_keys
            }
            self.update_objectid(**objectid_kwargs)

        if "process" in kwargs:
            process = kwargs.pop("process")
            if process:
                if isinstance(process, Process):
                    self.set_process(process)
                elif isinstance(process, Dict):
                    self.update_process(**process)

        # Remove objectid attributes
        kwargs = {
            key: value for key, value in kwargs.items() if key not in objectid_keys
        }
        update_object_items(self, kwargs)

    def update_process(self, **kwargs) -> None:
        """
        This method updates the process object attribute with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the process object attribute
        :return: None
        """
        if not self.process:
            self.process: Process = Process()
        self.process.update(**kwargs)

    def update_process_objectid(self, **kwargs) -> None:
        """
        This method updates the process ObjectID with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the process object attribute
        :return: None
        """
        if not self.process:
            self.process: Process = Process()
        self.process.update_objectid(**kwargs)

    def set_process(self, process: Process) -> None:
        """
        This method sets the process object attribute to the given process
        :param process: The given process object
        :return: None
        """
        self.process = process

    def create_tag(self, domain: Optional[str] = None) -> None:
        """
        This method creates the tag object for a network connection
        :param domain: The domain associated with the destination IP used in this network connection
        :return: None
        """
        if not domain and self.destination_ip is None:
            log.warning(
                "Cannot set tag for network connection. Requires either domain or destination IP..."
            )
            return
        if self.destination_port is None:
            log.warning(
                "Cannot set tag for network connection. Requires destination port..."
            )
            return

        if domain and self.direction == self.OUTBOUND:
            self.update_objectid(tag=f"{domain}:{self.destination_port}")
        # If no domain or if direction is inbound/unknown
        else:
            self.update_objectid(tag=f"{self.destination_ip}:{self.destination_port}")

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {
            key: value
            if (not isinstance(value, Process) and not isinstance(value, ObjectID))
            else value.as_primitives()
            for key, value in self.__dict__.items()
        }


class NetworkDNS:
    def __init__(
        self,
        connection_details: NetworkConnection = None,
        domain: str = None,
        resolved_ips: List[str] = None,
        lookup_type: str = None,
    ) -> None:
        """
        Details for a DNS request
        :param connection_details: The low-level details of the DNS request
        :param domain: The domain requested
        :param resolved_ips: A list of IPs that were resolved
        :param lookup_type: The type of DNS request
        :return: None
        """
        if isinstance(connection_details, NetworkConnection):
            self.connection_details: NetworkConnection = connection_details
        else:
            self.connection_details: NetworkConnection = NetworkConnection()

        self.domain: str = domain
        self.resolved_ips: List[str] = (
            resolved_ips if isinstance(resolved_ips, List) else []
        )
        self.lookup_type: str = lookup_type

    def update_process(self, **kwargs) -> None:
        """
        This method updates the process object attribute with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the process object attribute
        :return: None
        """
        if not self.connection_details.process:
            self.connection_details.process = Process()
        self.connection_details.process.update(**kwargs)

    def set_network_connection(self, network_connection: NetworkConnection) -> None:
        """
        This method sets the connection_details object attribute to the given network connection
        :param network_connection: The given network connection object
        :return: None
        """
        self.connection_details = network_connection

    def update_connection_details(self, **kwargs) -> None:
        """
        This method updates the connection_details object attribute with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the connection_details object attribute
        :return: None
        """
        self.connection_details.update(**kwargs)

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {
            key: value
            if (
                not isinstance(value, Process)
                and not isinstance(value, NetworkConnection)
            )
            else value.as_primitives()
            for key, value in self.__dict__.items()
        }


class NetworkHTTP:
    def __init__(
        self,
        connection_details: NetworkConnection = None,
        request_uri: str = None,
        request_headers: Dict[str, str] = None,
        request_body: str = None,
        request_method: str = None,
        response_headers: str = None,
        response_status_code: int = None,
        response_body: str = None,
        request_body_path: str = None,
        response_body_path: str = None,
    ) -> None:
        """
        Details for an HTTP request
        :param connection_details: The low-level details of the DNS request
        :param request_uri: The URI requested
        :param request_headers: Headers included in the request
        :param request_body: The body of the request
        :param request_method: The method of the request
        :param response_headers: The headers of the response
        :param response_status_code: The status code of the response
        :param response_body: The body of the response
        :param request_body_path: The path to the file containing the request body
        :param response_body_path: The path to the file containing the response body
        :return: None
        """
        if isinstance(connection_details, NetworkConnection):
            self.connection_details: NetworkConnection = connection_details
        else:
            self.connection_details: NetworkConnection = NetworkConnection()

        self.request_uri: str = request_uri
        self.request_headers: Dict[str, str] = (
            request_headers if isinstance(request_headers, Dict) else {}
        )
        self.request_body: str = request_body
        self.request_method: str = request_method
        self.response_headers: Dict[str, str] = (
            response_headers if isinstance(response_headers, Dict) else {}
        )
        self.response_status_code: int = response_status_code
        self.response_body: str = response_body
        self.request_body_path: str = request_body_path
        self.response_body_path: str = response_body_path

    def update(self, **kwargs) -> None:
        """
        This method updates networkhttp attributes with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the networkhttp attributes
        :return: None
        """
        if all(value is None for value in kwargs.values()):
            return

        if "process" in kwargs:
            process = kwargs.pop("process")
            if process:
                self.update_process(**process)

        if "connection_details" in kwargs:
            connection_details = kwargs.pop("connection_details")
            if connection_details:
                self.update_connection_details(**connection_details)

        update_object_items(self, kwargs)

    def update_process(self, **kwargs) -> None:
        """
        This method updates the process object attribute with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the process object attribute
        :return: None
        """
        if not self.connection_details.process:
            self.connection_details.process = Process()
        self.connection_details.process.update(**kwargs)

    def set_network_connection(self, network_connection: NetworkConnection) -> None:
        """
        This method sets the connection_details object attribute to the given network connection
        :param network_connection: The given network connection object
        :return: None
        """
        self.connection_details = network_connection

    def update_connection_details(self, **kwargs) -> None:
        """
        This method updates the connection_details object attribute with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the connection_details object attribute
        :return: None
        """
        self.connection_details.update(**kwargs)

    def get_process_image(self) -> Optional[str]:
        """
        This method returns the image of the process associated with the connection details
        :return: The image of the process associated with the connection details
        """
        if self.connection_details:
            if self.connection_details.process:
                return self.connection_details.process.image
        return None

    def get_process_pid(self) -> Optional[str]:
        """
        This method returns the pid of the process associated with the connection details
        :return: The pid of the process associated with the connection details
        """
        if self.connection_details:
            if self.connection_details.process:
                return self.connection_details.process.pid
        return None

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {
            key: value
            if (
                not isinstance(value, Process)
                and not isinstance(value, NetworkConnection)
            )
            else value.as_primitives()
            for key, value in self.__dict__.items()
            if key not in ["request_body_path", "response_body_path"]
        }


class SandboxOntology:
    class AnalysisMetadata:
        class MachineMetadata:
            def __init__(
                self,
                ip: str = None,
                hypervisor: str = None,
                hostname: str = None,
                platform: str = None,
                version: str = None,
                architecture: str = None,
            ) -> None:
                """
                The metadata regarding the machine where the analysis took place
                :param ip: The IP of the machine used for analysis
                :param hypervisor: The hypervisor of the machine used for analysis
                :param hostname: The name of the machine used for analysis
                :param platform: The platform of the machine used for analysis
                :param version: The version of the operating system of the machine used for analysis
                :param architecture: The architecture of the machine used for analysis
                """
                self.ip: str = ip
                self.hypervisor: str = hypervisor
                self.hostname: str = hostname
                self.platform: str = platform
                self.version: str = version
                self.architecture: str = architecture

            def as_primitives(self) -> Dict[str, Any]:
                """
                This method returns the dictionary representation of the object
                :return: The dictionary representation of the object
                """
                return {key: value for key, value in self.__dict__.items()}

            def load_from_json(self, json: Dict[str, Any]) -> None:
                """
                This method takes a given json and sets the corresponding attributes to those values
                :param json: The the given json representation of the machine metadata
                :return: None
                """
                self.ip = json["ip"]
                self.hypervisor = json["hypervisor"]
                self.hostname = json["hostname"]
                self.platform = json["platform"]
                self.version = json["version"]
                self.architecture = json["architecture"]

        def __init__(
            self,
            task_id: int = None,
            start_time: float = None,
            end_time: float = None,
            routing: str = None,
            machine_metadata: MachineMetadata = None,
        ) -> None:
            """
            The metadata of the analysis, per analysis
            :param task_id: The ID used for identifying the analysis task
            :param start_time: The start time of the analysis
            :param end_time: The end time of the analysis
            :param routing: The routing used in the sandbox setup (Spoofed, Internet, Tor, VPN)
            :param machine_metadata: The metadata of the analysis
            """
            self.task_id: int = task_id
            self.start_time: float = start_time
            self.end_time: float = end_time
            self.routing: str = routing
            self.machine_metadata = (
                machine_metadata
                if isinstance(
                    machine_metadata,
                    self.MachineMetadata,
                )
                else self.MachineMetadata()
            )

        def as_primitives(self) -> Dict[str, Any]:
            """
            This method returns the dictionary representation of the object
            :return: The dictionary representation of the object
            """
            return {
                key: value
                if not isinstance(value, self.MachineMetadata)
                else value.as_primitives()
                for key, value in self.__dict__.items()
            }

        def load_from_json(self, json: Dict[str, Any]) -> None:
            """
            This method takes a given json and sets the corresponding attributes to those values
            :param json: The the given json representation of the analysis metadata
            :return: None
            """
            self.task_id = json["task_id"]
            self.start_time = json["start_time"]
            self.end_time = json["end_time"]
            self.routing = json["routing"]
            self.machine_metadata.load_from_json(json["machine_metadata"])

    class Signature:
        class Subject:
            def __init__(
                self,
                ip: str = None,
                domain: str = None,
                uri: str = None,
                process: Process = None,
                file: str = None,
                registry: str = None,
            ) -> None:
                """
                An subject of interest, aka something interesting that the signature was raised on that is worth reporting
                :param ip: An IP that is a subject of interest
                :param domain: A domain that is a subject of interest
                :param uri: An URI that is a subject of interest
                :param process: A process that is a subject of interest
                :param file: A file path that is a subject of interest
                :param registry: A registry key that is a subject of interest
                """
                self.ip: str = ip
                self.domain: str = domain
                self.uri: str = uri
                self.file: str = file
                self.registry: str = registry

                if isinstance(process, Process):
                    self.process: Process = process
                else:
                    self.process = None

            def update_process(self, **kwargs) -> None:
                """
                This method updates the process object attribute with the given keyword arguments
                :param kwargs: Key word arguments to be used for updating the process object attribute
                :return: None
                """
                if not self.process:
                    self.process = Process()
                self.process.update(**kwargs)

            def set_process(self, process: Process) -> None:
                """
                This method sets the process object attribute to the given process
                :param process: The given process object
                :return: None
                """
                self.process = process

            def as_primitives(self) -> Dict[str, Any]:
                """
                This method returns the dictionary representation of the object
                :return: The dictionary representation of the object
                """
                return {
                    key: value
                    if not isinstance(value, Process)
                    else value.as_primitives()
                    for key, value in self.__dict__.items()
                }

        def __init__(
            self,
            process: Process = None,
            name: str = None,
            description: str = None,
            score: int = None,
            attack: List[Dict[str, Any]] = None,
            subjects: List[Subject] = None,
        ) -> None:
            """
            A signature that was raised during the analysis of the task
            :param process: The process associated with the signature
            :param name: The name of the signature
            :param description: The description of the signature
            :param score: An integer indicating the score of the signature
            :param attack: A list of Att&ck patterns and categories of the signature
            :param subjects: A list of subjects. A signature can have more than one subject.
            :return: None
            """
            if isinstance(process, Process):
                self.process: Process = process
            else:
                self.process = None

            self.name: str = name
            self.description: str = description
            self.score: int = score
            self.attack: List[Dict[str, Any]] = (
                attack
                if isinstance(attack, List) and all(isinstance(a, Dict) for a in attack)
                else []
            )
            self.subjects = (
                subjects
                if isinstance(subjects, List)
                and all(isinstance(s, self.Subject) for s in subjects)
                else []
            )

        def update(self, **kwargs) -> None:
            """
            This method updates the signature object with the given keyword arguments
            :param kwargs: Key word arguments to be used for updating the signature object
            :return: None
            """
            update_object_items(self, kwargs)

        def update_process(self, **kwargs) -> None:
            """
            This method updates the process object attribute with the given keyword arguments
            :param kwargs: Key word arguments to be used for updating the process object attribute
            :return: None
            """
            if all(value is None for value in kwargs.values()):
                return
            if not self.process:
                self.process = Process()
            self.process.update(**kwargs)

        def set_process(self, process: Optional[Process]) -> None:
            """
            This method sets the process object attribute to the given process
            :param process: The given process object
            :return: None
            """
            self.process = process

        def add_attack_id(self, attack_id: str) -> None:
            """
            This method adds an Att&ck ID to the signature's list of Att&ck IDs
            :param attack_id: The Att&ck ID to add
            :return: None
            """
            attack_item = None
            attack_id = revoke_map.get(attack_id, attack_id)
            current_attack_ids = [a["attack_id"] for a in self.attack]
            if attack_id in current_attack_ids:
                return

            if attack_id in attack_map:
                attack_item = dict(
                    attack_id=attack_id,
                    pattern=attack_map[attack_id]["name"],
                    categories=attack_map[attack_id]["categories"],
                )
            elif attack_id in software_map:
                attack_item = dict(
                    attack_id=attack_id,
                    pattern=software_map[attack_id].get("name", attack_id),
                    categories=["software"],
                )
            elif attack_id in group_map:
                attack_item = dict(
                    attack_id=attack_id,
                    pattern=group_map[attack_id].get("name", attack_id),
                    categories=["group"],
                )

            if attack_item:
                self.attack.append(attack_item)
            else:
                log.warning(f"Could not generate Att&ck output for ID: {attack_id}")

        def add_subject(self, **kwargs) -> None:
            """
            This method creates an subject and updates the subject's attributes with the given keyword arguments.
            Then this method adds the subject to the list of subjects for the signature.
            :param kwargs: Key word arguments to be used for updating the subject's attributes
            :return: None
            """
            if all(value is None for value in kwargs.values()):
                return
            if any(getattr(subject, k) == v for subject in self.subjects for k, v in kwargs.items()):
                return
            subject = self.Subject()
            update_object_items(subject, kwargs)
            self.subjects.append(subject)

        def add_process_subject(self, **kwargs) -> None:
            """
            This method creates an subject and updates the process object attribute with the given keyword arguments.
            Then this method adds the subject to the list of subjects for the signature.
            :param kwargs: Key word arguments to be used for updating the process object attribute of an subject
            :return: None
            """
            if all(value is None for value in kwargs.values()):
                return
            subject = self.Subject()
            subject.update_process(**kwargs)
            self.subjects.append(subject)

        def get_subjects(self) -> List[Subject]:
            """
            This method returns the subjects associated with the signature
            :return: The list of subjects associated with the signature
            """
            return self.subjects

        def as_primitives(self) -> Dict[str, Any]:
            """
            This method returns the dictionary representation of the object
            :return: The dictionary representation of the object
            """
            return {
                "process": self.process.as_primitives() if self.process else None,
                "name": self.name,
                "description": self.description,
                "attack": self.attack,
                "subjects": [subject.as_primitives() for subject in self.subjects],
            }

    def __init__(
        self,
        analysis_metadata: AnalysisMetadata = None,
        signatures: List[Signature] = None,
        network_connections: List[NetworkConnection] = None,
        network_dns: List[NetworkDNS] = None,
        network_http: List[NetworkHTTP] = None,
        processes: List[Process] = None,
        sandbox_name: str = None,
        sandbox_version: str = None,
    ) -> None:
        """
        The result ontology for sandbox output
        :param analysis_metadata: Metadata for the analysis
        :param signatures: Signatures that the file may have
        :param network_connections: The IP traffic observed during analysis
        :param network_dns: The DNS traffic observed during analysis
        :param network_http: The HTTP traffic observed during analysis
        :param processes: A list of processes
        :param sandbox_name: The name of the sandbox
        :param sandbox_version: The version of the sandbox
        :return: None
        """
        self.analysis_metadata = (
            analysis_metadata
            if isinstance(analysis_metadata, self.AnalysisMetadata)
            else self.AnalysisMetadata()
        )
        self.signatures = (
            signatures
            if isinstance(signatures, List)
            and all(
                isinstance(signature, SandboxOntology.Signature)
                for signature in signatures
            )
            else []
        )
        self.network_connections: List[NetworkConnection] = (
            network_connections
            if isinstance(network_connections, List)
            and all(
                isinstance(network_connection, NetworkConnection)
                for network_connection in network_connections
            )
            else []
        )
        self.network_dns: List[NetworkDNS] = (
            network_dns
            if isinstance(network_dns, List)
            and all(isinstance(dns, NetworkDNS) for dns in network_dns)
            else []
        )
        self.network_http: List[NetworkHTTP] = (
            network_http
            if isinstance(network_http, List)
            and all(isinstance(http, NetworkHTTP) for http in network_http)
            else []
        )
        self.processes: List[Process] = (
            processes
            if isinstance(processes, List)
            and all(isinstance(process, Process) for process in processes)
            else []
        )
        self.sandbox_name: str = sandbox_name
        self.sandbox_version: str = sandbox_version
        self._guid_process_map: Dict[str, Process] = {}

    def update_analysis_metadata(self, **kwargs) -> None:
        """
        This method updates the analysis_metadata object attribute with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the analysis_metadata object attribute
        :return: None
        """
        update_object_items(self.analysis_metadata, kwargs)

    def update_machine_metadata(self, **kwargs) -> None:
        """
        This method updates the machine_metadata object attribute with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the machine_metadata object attribute
        :return: None
        """
        update_object_items(self.analysis_metadata.machine_metadata, kwargs)

    def create_process(self, **kwargs) -> Process:
        """
        This method creates a Process object, assigns it's attributes based on keyword arguments provided,
        and returns the Process object
        :param kwargs: Key word arguments to be used for updating the Process object's attributes
        :return: Process object
        """
        process = Process()
        process.update(**kwargs)

        if not process.objectid.guid:
            process.objectid.assign_guid()
        if not process.pobjectid.guid:
            process.pobjectid.assign_guid()
        if not process.start_time:
            process.set_start_time(float("-inf"))
        if not process.end_time:
            process.set_end_time(float("inf"))
        if not process.objectid.time_observed:
            process.objectid.set_time_observed(process.start_time)
        return process

    def add_process(self, process: Process) -> None:
        """
        This method adds a validated Process object to the list of processes
        :param process: The Process object to be added
        :return: None
        """
        if self._validate_process(process):
            self._guid_process_map[process.objectid.guid] = process
            self.set_parent_details(process)
            self.set_child_details(process)
            self.processes.append(process)
        else:
            log.warning("Invalid process, ignoring...")
            return

    def update_process(self, **kwargs) -> None:
        """
        This method updates a Process object attributes
        :param kwargs: Key word arguments to be used for updating the Process object's attributes
        :return: None
        """
        if all(value is None for value in kwargs.values()):
            return

        if "guid" not in kwargs and "pid" not in kwargs:
            log.warning(
                "You must pass GUID kwarg or a PID kwarg if you want to update a process"
            )
            return
        elif (
            "guid" not in kwargs
            and "pid" in kwargs
            and not ("start_time" in kwargs or "end_time" in kwargs)
        ):
            log.warning(
                "You must pass GUID kwarg or a PID kwarg with a timestamp such as start_time or end_time if you want to update a process."
            )
            return

        # Don't update the parent yet
        parent_keys = ["pguid", "ptag", "ptreeid", "pprocesstree",
                       "ptime_observed", "ppid", "pimage", "pcommand_line", "pobjectid"]
        parent_kwargs = {
            key[1:]: value for key, value in kwargs.items() if key in parent_keys
        }
        kwargs = {
            key: value
            for key, value in kwargs.items()
            if key not in parent_keys
        }

        if "guid" in kwargs:
            process_to_update = self.get_process_by_guid(kwargs["guid"])
            if not process_to_update:
                p = self.create_process(**kwargs)
                self.add_process(p)
                return
            process_to_update.update(**kwargs)
        else:
            timestamp = (
                kwargs["end_time"] if kwargs.get("end_time") else kwargs["start_time"]
            )
            guid = self.get_guid_by_pid_and_time(kwargs["pid"], timestamp)
            if not guid:
                p = self.create_process(**kwargs)
                self.add_process(p)
                return
            process_to_update = self.get_process_by_guid(guid)
            kwargs["guid"] = guid
            process_to_update.update(**kwargs)

        if parent_kwargs.get("guid") or parent_kwargs.get("pobjectid", {}).get("guid"):
            # Only update if ObjectID is not associated with another process
            if any(process_to_update.pobjectid == process.objectid for process in self.get_processes()):
                return
            pguid = parent_kwargs["guid"] if parent_kwargs.get(
                "guid") else parent_kwargs.get("pobjectid", {}).get("guid")
            parent = self.get_process_by_guid(pguid)
            process_to_update.set_parent(parent)

    def update_objectid(self, **kwargs) -> None:
        """
        This method updates an object's ObjectID attributes
        :param kwargs: Key word arguments to be used for updating the object's ObjectID attributes
        :return: None
        """
        if all(value is None for value in kwargs.values()):
            return

        if "guid" not in kwargs:
            log.warning(
                "You must pass GUID kwarg if you want to update a process ObjectID."
            )
            return

        object_to_update = self.get_process_by_guid(kwargs["guid"])
        if not object_to_update:
            object_to_update = self.get_network_connection_by_guid(kwargs["guid"])
            if not object_to_update:
                return

        update_object_items(object_to_update.objectid, kwargs)

    def set_parent_details(self, process: Process) -> None:
        """
        This method sets the parent process's details in the given process
        :param process: The process that will have it's parent's details set
        :return: None
        """
        parent = None
        if process.pobjectid.guid:
            parent = self.get_process_by_guid(process.pobjectid.guid)
            process.set_parent(parent)

        if not parent and process.ppid and process.start_time:
            parent_guid = self.get_guid_by_pid_and_time(
                process.ppid, process.start_time
            )
            parent = self.get_process_by_guid(parent_guid)
            process.set_parent(parent)

    def set_child_details(self, process: Process) -> None:
        """
        This method sets the parent process details for any child processes of the given process
        :param process: The parent process that will be set as the parent for any associated child processes
        :return: None
        """
        if process.objectid.guid:
            child_processes = self.get_processes_by_pguid(process.objectid.guid)
            for child_process in child_processes:
                child_process.set_parent(process)
        # Processes may not have a pguid attribute set, so this is not an elif case
        if process.pid and process.start_time:
            child_processes = self.get_processes_by_ppid_and_time(
                process.pid, process.start_time
            )
            for child_process in child_processes:
                child_process.set_parent(process)

    def get_processes(self) -> List[Process]:
        """
        This method is a getter for the processes attribute
        :return: The value of the processes attribute
        """
        return self.processes

    def get_guid_by_pid_and_time(self, pid: int, timestamp: float) -> Optional[str]:
        """
        This method allows the retrieval of GUIDs based on a process ID and timestamp
        :param pid: The process ID
        :param timestamp: A timestamp between the creation and termination of a process
        :return: The GUID for the given process ID
        """
        process = self.get_process_by_pid_and_time(pid, timestamp)
        if process:
            return process.objectid.guid
        else:
            return None

    def get_processes_by_ppid_and_time(
        self, ppid: int, timestamp: float
    ) -> List[Process]:
        """
        This method allows the retrieval of processes based on a parent process ID and timestamp
        :param ppid: The parent process ID
        :param timestamp: A timestamp between the creation and termination of a process
        :return: The child processes associated for the given parent process ID
        """
        if timestamp is None:
            return None
        return [
            process
            for process in self.get_processes()
            if process.ppid == ppid
            and timestamp <= process.end_time
            and timestamp >= process.start_time
        ]

    def get_pguid_by_pid_and_time(self, pid: int, timestamp: float) -> Optional[str]:
        """
        This method allows the retrieval of the parent process's GUID based on a process ID and timestamp
        :param pid: The process ID
        :param timestamp: A timestamp between the creation and termination of a process
        :return: The parent process's GUID for the given process ID
        """
        process = self.get_process_by_pid_and_time(pid, timestamp)
        if process:
            return process.pobjectid.guid
        else:
            return None

    def is_guid_in_gpm(self, guid: str) -> bool:
        """
        This method confirms if a GUID is in the GUID -> Process map
        :return: A boolean indicating if a GUID is in the GUID -> Process map
        """
        return f"{{{str(UUID(guid)).upper()}}}" in self._get_guids()

    def get_process_by_guid(self, guid: Optional[str]) -> Optional[Process]:
        """
        This method takes a given GUID and returns the associated process
        :param guid: The given GUID that we want an associated process for
        :return: The associated process
        """
        if guid is None:
            return None
        return self._guid_process_map.get(guid.upper())

    def get_process_by_command_line(self, command_line: Optional[str] = None) -> Optional[Process]:
        """
        This method takes a given command line and returns the associated process
        NOTE That this method has a high possibility of not being accurate. If multiple processes use the same
        command line, this method will return the first process.
        :param command_line: The given command line that we want an associated process for
        :return: The associated process
        """
        if not command_line:
            return None

        processes_with_command_line = [process for process in self.get_processes() if process.command_line and (
            command_line == process.command_line or command_line in process.command_line)]
        if not processes_with_command_line:
            return None
        else:
            return processes_with_command_line[0]

    def get_network_connection_by_guid(
        self, guid: Optional[str]
    ) -> Optional[NetworkConnection]:
        """
        This method takes a given GUID and returns the associated network connection
        :param guid: The given GUID that we want an associated network connection for
        :return: The associated network connection
        """
        if guid is None:
            return None

        network_connections_with_guid = [
            network_connection
            for network_connection in self.get_network_connections()
            if network_connection.objectid.guid == guid
        ]

        if not network_connections_with_guid:
            return None
        else:
            return network_connections_with_guid[0]

    def get_process_by_pid_and_time(
        self, pid: Optional[int], timestamp: Optional[float]
    ) -> Optional[Process]:
        """
        This method allows the retrieval of a process based on a process ID and timestamp
        :param pid: The process ID
        :param timestamp: A timestamp between the creation and termination of a process
        :return: The process for the given process ID
        """
        if pid is None or timestamp is None:
            return None
        processes: List[Process] = [
            process
            for process in self.get_processes()
            if process.pid == pid
            and timestamp <= process.end_time
            and timestamp >= process.start_time
        ]
        if not processes:
            return None
        elif len(processes) > 1:
            log.warning("Map is invalid")
            return None
        else:
            return processes[0]

    def get_processes_by_pguid(self, pguid: Optional[str]) -> List[Process]:
        """
        This method takes a given parent process GUID and returns the child processes
        :param guid: The given parent process GUID that we want the child processes for
        :return: The child processes
        """
        if pguid is None:
            return []
        return [
            process
            for process in self.get_processes()
            if process.pobjectid.guid == pguid
        ]

    def create_network_connection(self, **kwargs) -> NetworkConnection:
        """
        This method creates a NetworkConnection object, assigns it's attributes based on keyword arguments provided,
        and returns the NetworkConnection object
        :param kwargs: Key word arguments to be used for updating the NetworkConnection object's attributes
        :return: NetworkConnection object
        """
        network_connection = NetworkConnection()
        network_connection.update(**kwargs)
        return network_connection

    def add_network_connection(self, network_connection: NetworkConnection) -> None:
        """
        This method adds a NetworkConnection object to the list of network connections
        :param network_connection: The NetworkConnection object to be added
        :return: None
        """
        # Check if network_connection.process needs linking
        if network_connection.process:
            if network_connection.process.objectid.guid:
                guid = network_connection.process.objectid.guid
            else:
                guid = self.get_guid_by_pid_and_time(
                    network_connection.process.pid,
                    network_connection.process.start_time,
                )
            process_to_point_to = self.get_process_by_guid(guid)
            # If we cannot link a process to this network connection, then don't include the process
            network_connection.set_process(process_to_point_to)

        domain = self.get_domain_by_destination_ip(network_connection.destination_ip)
        network_connection.create_tag(domain)

        self.network_connections.append(network_connection)

    def get_network_connections(self) -> List[NetworkConnection]:
        """
        This method returns the network connections
        :return: The list of network connections
        """
        return self.network_connections

    def get_network_connection_by_pid(self, pid: int) -> List[NetworkConnection]:
        """
        This method allows the retrieval of network connections that match a certain process ID
        :param pid: The process ID
        :return: A list of signatures that match the process pid
        """
        return [
            network_connection
            for network_connection in self.get_network_connections()
            if getattr(network_connection.process, "pid", None) == pid
        ]

    def get_network_connection_by_details(
        self,
        source_ip: str,
        source_port: int,
        destination_ip: str,
        destination_port: int,
        direction: str,
        transport_layer_protocol: str,
    ) -> NetworkConnection:
        """
        This method finds an existing network connection based on specific details
        :param source_ip: The source IP of the network connection
        :param source_port: The source port of the network connection
        :param destination_ip: The destination IP of the network connection
        :param destination_port: The destination port of the network connection
        :param direction: The direction of the network connection
        :param transport_layer_protocol: The transport layer protocol of the connection
        :return: The matching network connection, if it exists
        """
        # All or nothing!
        if any(
                item is None
                for item in
                [source_ip, source_port, destination_ip, destination_port, direction, transport_layer_protocol]):
            return None

        # Due to the way INetSim traffic can be handled, let's check for network connections that are both HTTP and HTTPS
        if destination_port == 80:
            destination_ports = [80, 443]
        else:
            destination_ports = [destination_port]

        for network_connection in self.get_network_connections():
            if (
                network_connection.source_ip == source_ip
                and network_connection.source_port == source_port
                and network_connection.destination_ip == destination_ip
                and network_connection.destination_port in destination_ports
                and network_connection.direction == direction
                and network_connection.transport_layer_protocol == transport_layer_protocol
            ):
                return network_connection
        return None

    def create_network_dns(self, **kwargs) -> NetworkDNS:
        """
        This method creates a NetworkDNS object, assigns it's attributes based on keyword arguments provided,
        and returns the NetworkDNS object
        :param kwargs: Key word arguments to be used for updating the NetworkDNS object's attributes
        :return: NetworkDNS object
        """
        network_dns = NetworkDNS()
        if "connection_details" in kwargs:
            network_dns.set_network_connection(kwargs.pop("connection_details"))
        update_object_items(network_dns, kwargs)
        return network_dns

    def add_network_dns(self, dns: NetworkDNS) -> None:
        """
        This method adds a NetworkDNS object to the list of network DNS calls
        :param dns: The NetworkDNS object to be added
        :return: None
        """
        # Check if connection_details needs linking
        if dns.connection_details:
            network_connection_to_point_to = self.get_network_connection_by_details(
                dns.connection_details.source_ip,
                dns.connection_details.source_port,
                dns.connection_details.destination_ip,
                dns.connection_details.destination_port,
                dns.connection_details.direction,
                dns.connection_details.transport_layer_protocol,
            )
            if network_connection_to_point_to:
                dns.set_network_connection(network_connection_to_point_to)
            else:
                # Autofill default fields
                if not dns.connection_details.destination_port:
                    dns.update_connection_details(destination_port=53)
                if not dns.connection_details.direction:
                    dns.update_connection_details(direction="outbound")
                if not dns.connection_details.transport_layer_protocol:
                    dns.update_connection_details(transport_layer_protocol="udp")

                self.add_network_connection(dns.connection_details)

        dns.connection_details.create_tag(dns.domain)
        self.network_dns.append(dns)

    def get_network_dns(self) -> List[NetworkDNS]:
        """
        This method returns the network dns
        :return: The list of network dns
        """
        return self.network_dns

    def get_domain_by_destination_ip(self, ip: str) -> Optional[str]:
        """
        This method returns domains associated with a given destination IP
        :param ip: The IP for which an associated domain is requested
        :return: The domain associated with the given destination IP
        """
        domains = [dns.domain for dns in self.network_dns if ip in dns.resolved_ips]
        if domains:
            return domains[0]
        else:
            return None

    def get_destination_ip_by_domain(self, domain: str) -> Optional[str]:
        """
        This method returns a destination ip associated with a given domain
        :param domain: The domain for which an associated IP is requested
        :return: The IP associated with the given domain
        """
        ips = [dns.resolved_ips[0] for dns in self.network_dns if domain == dns.domain]
        if ips:
            return ips[0]
        else:
            return None

    def create_network_http(self, **kwargs) -> NetworkHTTP:
        """
        This method creates a NetworkHTTP object, assigns it's attributes based on keyword arguments provided,
        and returns the NetworkHTTP object
        :param kwargs: Key word arguments to be used for updating the NetworkHTTP object's attributes
        :return: NetworkHTTP object
        """
        network_http = NetworkHTTP()
        if "connection_details" in kwargs:
            network_http.set_network_connection(kwargs.pop("connection_details"))
        update_object_items(network_http, kwargs)
        return network_http

    def add_network_http(self, http: NetworkHTTP) -> None:
        """
        This method adds a NetworkHTTP object to the list of network HTTP calls
        :param http: The NetworkHTTP object to be added
        :return: None
        """
        # Check if connection_details needs linking
        if http.connection_details:
            network_connection_to_point_to = self.get_network_connection_by_details(
                http.connection_details.source_ip,
                http.connection_details.source_port,
                http.connection_details.destination_ip,
                http.connection_details.destination_port,
                http.connection_details.direction,
                http.connection_details.transport_layer_protocol,
            )
            if network_connection_to_point_to:
                http.set_network_connection(network_connection_to_point_to)
            else:
                # Autofill default fields
                if not http.connection_details.destination_port:
                    http.update_connection_details(destination_port=80)
                if not http.connection_details.direction:
                    http.update_connection_details(direction="outbound")
                if not http.connection_details.transport_layer_protocol:
                    http.update_connection_details(transport_layer_protocol="tcp")

                self.add_network_connection(http.connection_details)

        self.network_http.append(http)

    def get_network_http(self) -> List[NetworkHTTP]:
        """
        This method returns the network HTTP
        :return: The list of network HTTP
        """
        return self.network_http

    def get_network_http_by_path(self, path: str) -> Optional[NetworkHTTP]:
        """
        This method returns the network HTTP call associated with a path
        :param path: The path to a response/request body file
        :return: The associated network HTTP call for the given path
        """
        network_http_with_path = [
            http
            for http in self.get_network_http()
            if http.response_body_path == path or http.request_body_path == path
        ]
        if not network_http_with_path:
            return None
        else:
            return network_http_with_path[0]

    def get_network_http_by_details(
            self, request_uri: str, request_method: str, request_headers: Dict[str, str]) -> Optional[NetworkHTTP]:
        """
        This request_method gets a network http call by request URI, request_method and request headers
        :param request_uri: The URI of the request
        :param request_method: The request_method used for the HTTP request
        :param request_headers: The headers of the request
        :return: The network http call (should one exist) that matches these details
        """
        network_http_with_details = [
            http for http in self.get_network_http()
            if http.request_uri == request_uri and
            http.request_method == request_method and
            http.request_headers == request_headers
        ]
        if not network_http_with_details:
            return None
        else:
            return network_http_with_details[0]

    def create_signature(self, **kwargs) -> Signature:
        """
        This method creates a Signature object, assigns it's attributes based on keyword arguments provided,
        and returns the Signature object
        :param kwargs: Key word arguments to be used for updating the Signature object's attributes
        :return: Signature object
        """
        signature = SandboxOntology.Signature()
        if "description" in kwargs:
            kwargs["description"] = kwargs["description"].lower()
        update_object_items(signature, kwargs)
        return signature

    def add_signature(self, signature: Signature) -> None:
        """
        This method adds a Signature object to the list of signatures
        :param signature: The Signature object to be added
        :return: None
        """
        if signature.process:
            if signature.process.objectid.guid:
                guid = signature.process.objectid.guid
            else:
                guid = self.get_guid_by_pid_and_time(
                    signature.process.pid, signature.process.start_time
                )
            process_to_point_to = self.get_process_by_guid(guid)
            signature.set_process(process_to_point_to)

        process_subjects: Set[Process] = set()
        for subject in signature.subjects:
            if subject.process:
                if subject.process.objectid.guid:
                    guid = subject.process.objectid.guid
                else:
                    guid = self.get_guid_by_pid_and_time(
                        subject.process.pid, subject.process.start_time
                    )
                process_to_point_to = self.get_process_by_guid(guid)
                if process_to_point_to:
                    # No duplicates
                    if process_to_point_to in process_subjects:
                        subject.process = None
                    else:
                        subject.set_process(process_to_point_to)
                        process_subjects.add(process_to_point_to)
                else:
                    subject.process = None

        for subject in signature.subjects[:]:
            if all(value is None for value in subject.as_primitives().values()):
                signature.subjects.remove(subject)

        # Confirm that the signature is still worth reporting
        if all(not value for value in signature.as_primitives().values()):
            return

        self.signatures.append(signature)

    def get_signatures(self) -> List[Signature]:
        """
        This method is a getter for the signatures attribute
        :return: The value of the signatures attribute
        """
        return self.signatures

    def get_signatures_by_pid(self, pid: int) -> List[Signature]:
        """
        This method allows the retrieval of signatures that match a certain process ID
        :param pid: The process ID
        :return: A list of signatures that match the process pid
        """
        return [
            signature
            for signature in self.signatures
            if getattr(signature.process, "pid", None) == pid
        ]

    def set_sandbox_name(self, sandbox_name) -> None:
        """
        This method sets the sandbox name attribute
        :param sandbox_name: The new value of the sandbox name
        :return: None
        """
        self.sandbox_name = sandbox_name

    def set_sandbox_version(self, sandbox_version) -> None:
        """
        This method sets the sandbox version attribute
        :param sandbox_version: The new value of the sandbox version
        :return: None
        """
        self.sandbox_version = sandbox_version

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {
            "analysis_metadata": self.analysis_metadata.as_primitives(),
            "signatures": [signature.as_primitives() for signature in self.signatures],
            "network_connections": [
                network_connection.as_primitives()
                for network_connection in self.network_connections
            ],
            "network_dns": [
                network_dns.as_primitives() for network_dns in self.network_dns
            ],
            "network_http": [
                network_http.as_primitives() for network_http in self.network_http
            ],
            "processes": [process.as_primitives() for process in self.processes],
            "sandbox_name": self.sandbox_name,
            "sandbox_version": self.sandbox_version,
        }

    def get_events(self, safelist: List[str] = None) -> List[Union[Process, NetworkConnection]]:
        """
        This method gets all process and network events, sorts them by time observed, and returns a list
        :param safelist: A list of safe treeids
        :return: A sorted list of all process and network events
        """
        if safelist is None:
            safelist: List[str] = []

        events = [process for process in self.processes
                  if process.start_time is not None and process.objectid.treeid not in safelist] + [network_connection
                                                                                                    for network_connection in self.network_connections
                                                                                                    if network_connection.objectid.time_observed is not None and network_connection.objectid.treeid
                                                                                                    not in safelist]
        return self._sort_things_by_time_observed(events)

    def get_non_safelisted_processes(self, safelist: List[str]) -> List[Process]:
        """
        This method filters events by their tree ID and returns the remaining events
        :param safelist: All of the safe leaf tree IDs (the safelist)
        :return: A list of non-safelisted process
        """
        # NOTE: This method must be called once tree IDs have been added to the process_event_dicts, most likely
        # through calculating the process tree
        filtered_processes = [
            process
            for process in self.get_processes()
            if process.objectid.treeid not in safelist
        ]
        sorted_filtered_processes = self._sort_things_by_time_observed(
            filtered_processes
        )
        return sorted_filtered_processes

    def get_process_tree(self, safelist: List[str] = None) -> List[Dict[str, Any]]:
        """
        This method generates the event tree
        :return: The event tree
        """
        if safelist is None:
            safelist: List[str] = []
        events = self.get_events()
        events_dict = self._convert_events_to_dict(events)
        tree = self._convert_events_dict_to_tree(events_dict)
        self._create_treeids(tree)
        if safelist:
            tree = SandboxOntology._filter_event_tree_against_safe_treeids(
                tree, safelist
            )
        return tree

    def get_process_tree_result_section(
        self, safelist: List[str] = None
    ) -> ResultProcessTreeSection:
        """
        This method creates the Typed ResultSection for Process (Event) Trees
        :param safelist: A safelist of tree IDs that is to be applied to the events
        :return: The Typed ResultSection for the Process (Event) Tree
        """
        if safelist is None:
            safelist: List[str] = []
        tree = self.get_process_tree(safelist)
        items: List[ProcessItem] = []
        process_tree_result_section = ResultProcessTreeSection("Spawned Process Tree")
        for event in tree:
            # A telltale sign that the event is a NetworkConnection
            if "process" in event:
                # event is a NetworkConnection, we don't want this in the process tree result section, only the counts
                continue
            self._convert_event_tree_to_result_section(items, event, safelist, process_tree_result_section)
        for item in items:
            process_tree_result_section.add_process(item)
        return process_tree_result_section

    def load_from_json(self, json: Dict[str, Any]) -> None:
        """
        This method takes a given json and sets the corresponding attributes to those values
        :param json: The the given json representation of the sandbox ontology
        :return: None
        """
        self.analysis_metadata.load_from_json(json["analysis_metadata"])
        for signature in json["signatures"]:
            self.signatures.append(self._load_signature_from_json(signature))
        for network_connection in json["network_connections"]:
            self.network_connections.append(
                self._load_network_connection_from_json(network_connection)
            )
        for dns in json["network_dns"]:
            self.network_dns.append(self._load_network_dns_from_json(dns))
        for http in json["network_http"]:
            self.network_http.append(self._load_network_http_from_json(http))
        for process in json["processes"]:
            self.processes.append(self._load_process_from_json(process))
        self.sandbox_name = json["sandbox_name"]
        self.sandbox_version = json["sandbox_version"]

    @staticmethod
    def handle_artifacts(
        artifact_list: List[Dict[str, Any]],
        request: ServiceRequest,
        collapsed: bool = False,
    ) -> ResultSection:
        """
        Goes through each artifact in artifact_list, uploading them and adding result sections accordingly
        :param artifact_list: List of dictionaries that each represent an artifact
        :param collapsed: A flag used for indicating if the Sandbox Artifacts ResultSection should be collapsed or not
        :return: A ResultSection containing any Artifact ResultSections
        """

        validated_artifacts = SandboxOntology._validate_artifacts(artifact_list)

        artifacts_result_section = ResultSection(
            "Sandbox Artifacts", auto_collapse=collapsed
        )

        for artifact in validated_artifacts:
            SandboxOntology._handle_artifact(artifact, artifacts_result_section)

            if artifact.to_be_extracted:
                try:
                    request.add_extracted(
                        artifact.path, artifact.name, artifact.description
                    )
                except MaxExtractedExceeded:
                    # To avoid errors from being raised when too many files have been extracted
                    pass
            else:
                request.add_supplementary(
                    artifact.path, artifact.name, artifact.description
                )

        return (
            artifacts_result_section if artifacts_result_section.subsections else None
        )

    def _get_guids(self) -> List[str]:
        """
        This method gets a list of GUIDs from the GUID - PID map
        :return: A list of GUIDs
        """
        return list(self._guid_process_map.keys())

    def _validate_process(self, process: Process) -> bool:
        """
        This method validates a Process object
        :param process: A Process object to be validated
        :return: A boolean flag indicating that Process is valid
        """
        # Grab pids and guids to use for validation
        pids: List[int] = [
            process.pid
            for process in self._guid_process_map.values()
            if process.pid is not None
        ]
        guids: List[str] = list(self._guid_process_map.keys())

        if process.objectid.guid is None and process.pid is None:
            log.warning("Process requires at least a GUID or a PID, skipping...")
            return False
        elif not process.objectid.guid and process.pid not in pids:
            # This means we have a unique process that is not yet in the lookup table.
            # Before we add it, assign a GUID to it.
            process.objectid.assign_guid()
        elif process.objectid.guid in guids and process.pid in pids:
            # We cannot have two items in the table that share process IDs and GUIDs
            log.warning("Duplicate process, skipping...")
            return False
        elif process.objectid.guid in guids and process.pid not in pids:
            # We cannot have two items in the table that share GUIDs
            log.warning("Duplicate process, skipping...")
            return False
        elif process.objectid.guid not in guids and process.pid in pids:
            # We can have two items in the table that share PIDs that don't share GUIDs
            # Further validation is required
            return self._handle_pid_match(process)
        else:
            # process.guid and process.guid not in guids and process.pid not in pids
            # We have a unique process that is not yet in the lookup table and has a GUID.
            # Add it!
            pass
        return True

    def _handle_pid_match(self, process: Process) -> bool:
        """
        This method is a deeper step in process validation for processes that share IDs
        :param process: A Process object that shares an ID with another Process object in the lookup table
        :return: A boolean indicating if process is a valid entry
        """
        valid_entry = False
        # We only care about processes that share process IDs
        processes_with_common_pids = [
            validated_process
            for validated_process in self.processes
            if validated_process.pid == process.pid
        ]

        if not processes_with_common_pids:
            return True

        for process_with_common_pid in processes_with_common_pids:
            if (
                process_with_common_pid.start_time == process.start_time
                and process_with_common_pid.end_time == process.end_time
            ):
                # We cannot have multiple processes that share IDs that took place at the same time
                continue
            elif (
                process.start_time >= process_with_common_pid.end_time
                or process.end_time <= process_with_common_pid.start_time
            ):
                # We can only have multiple processes that share IDs if they did not take place at the same time
                valid_entry = True
            else:
                # We cannot have multiple processes that share IDs that have overlapping time ranges
                continue
        return valid_entry

    def _remove_process(self, process: Process) -> None:
        """
        This method takes a process and removes it from the current processes, if it exists
        :param process: The process to be removed
        :return: None
        """
        try:
            self.processes.remove(process)
        except ValueError:
            return

    def _remove_network_http(self, network_http: NetworkHTTP) -> None:
        """
        This method takes a network_http and removes it from the current network_http calls, if it exists
        :param network_http: The network_http to be removed
        :return: None
        """
        try:
            self.network_http.remove(network_http)
        except ValueError:
            return

    def _remove_network_dns(self, network_dns: NetworkDNS) -> None:
        """
        This method takes a network_dns and removes it from the current network_dns calls, if it exists
        :param network_dns: The network_dns to be removed
        :return: None
        """
        try:
            self.network_dns.remove(network_dns)
        except ValueError:
            return

    def _remove_network_connection(self, network_connection: NetworkConnection) -> None:
        """
        This method takes a network_connection and removes it from the current network_connections, if it exists
        :param network_connection: The network_connection to be removed
        :return: None
        """
        try:
            self.network_connections.remove(network_connection)
        except ValueError:
            return

    def _remove_signature(self, signature: Signature) -> None:
        """
        This method takes a signature and removes it from the current signatures, if it exists
        :param signature: The signature to be removed
        :return: None
        """
        try:
            self.signatures.remove(signature)
        except ValueError:
            return

    def _load_process_from_json(self, json: Dict[str, Any]) -> Process:
        """
        This method takes a given json and sets the corresponding attributes to those values
        :param json: The the given json representation of the process
        :return: A process object
        """
        process = self.create_process(**json)
        return process

    def _load_signature_from_json(self, json: Dict[str, Any]) -> Signature:
        """
        This method takes a given json and sets the corresponding attributes to those values
        :param json: The the given json representation of the signature
        :return: A signature object
        """
        process = json.pop("process")
        subjects = json.pop("subjects")
        signature = self.create_signature(**json)
        if process:
            signature.update_process(**process)
        if subjects:
            for subject in subjects:
                subject_process = subject.pop("process")
                if subject_process:
                    signature.add_process_subject(**subject_process)
                else:
                    signature.add_subject(**subject)
        return signature

    def _load_network_connection_from_json(
        self, json: Dict[str, Any]
    ) -> NetworkConnection:
        """
        This method takes a given json and sets the corresponding attributes to those values
        :param json: The the given json representation of the network connection
        :return: A network connection object
        """
        process = json.pop("process")
        network_connection = self.create_network_connection(**json)
        if process:
            network_connection.update_process(**process)
        return network_connection

    def _load_network_dns_from_json(self, json: Dict[str, Any]) -> NetworkDNS:
        """
        This method takes a given json and sets the corresponding attributes to those values
        :param json: The the given json representation of the network dns
        :return: A network dns object
        """
        connection_details = json.pop("connection_details")
        network_dns = self.create_network_dns(**json)
        if connection_details:
            process = connection_details.pop("process")
            network_dns.connection_details.update(**connection_details)
            if process:
                network_dns.update_process(**process)
        return network_dns

    def _load_network_http_from_json(self, json: Dict[str, Any]) -> NetworkHTTP:
        """
        This method takes a given json and sets the corresponding attributes to those values
        :param json: The the given json representation of the network http
        :return: A network http object
        """
        connection_details = json.pop("connection_details")
        network_http = self.create_network_http(**json)
        if connection_details:
            process = connection_details.pop("process")
            network_http.connection_details.update(**connection_details)
            if process:
                network_http.update_process(**process)
        return network_http

    @staticmethod
    def _sort_things_by_time_observed(
        things_to_sort_by_time_observed: List[Union[Process, NetworkConnection, Dict]]
    ) -> List[Any]:
        """
        This method sorts a list of things by their time_observeds
        :param things_to_sort_by_time_observed: A list of things to sort by time_observed
        :return: A list of things that have been sorted by time_observed
        """
        if not things_to_sort_by_time_observed:
            return []

        # If every item is a dictionary, then use key lookups
        if all(
            isinstance(thing_to_sort_by_time_observed, Dict)
            for thing_to_sort_by_time_observed in things_to_sort_by_time_observed
        ):

            if any(
                thing_to_sort_by_time_observed["objectid"]["time_observed"] is None
                for thing_to_sort_by_time_observed in things_to_sort_by_time_observed
            ):
                log.warning("All ObjectID time_observed values must not be None...")
                return things_to_sort_by_time_observed

            def time_observed(x):
                return x["objectid"]["time_observed"]

        else:

            if any(
                thing_to_sort_by_time_observed.objectid.time_observed is None
                for thing_to_sort_by_time_observed in things_to_sort_by_time_observed
            ):
                log.warning("All ObjectID time_observed values must not be None...")
                return things_to_sort_by_time_observed

            def time_observed(x):
                return x.objectid.time_observed

        sorted_things = sorted(things_to_sort_by_time_observed, key=time_observed)
        return sorted_things

    @staticmethod
    def _sort_things_by_relationship(
            things_to_sort_by_relationship: List[Union[Process, NetworkConnection, Dict]]) -> List[
            Union[Process, NetworkConnection, Dict]]:
        """
        This method sorts a list of things by their relationships
        :param things_to_sort_by_relationship: A list of things to sort by their relationships to one another
        :return: A list of things that have been sorted by their relationships
        """
        if not things_to_sort_by_relationship:
            return []

        recurse_again = False
        # If every item is a dictionary, then use key lookups
        if all(
            isinstance(thing_to_sort, Dict)
            for thing_to_sort in things_to_sort_by_relationship
        ):
            for index, thing in enumerate(things_to_sort_by_relationship[:]):
                # Confirm if we are working with an process or a network
                if "pobjectid" in thing:
                    # This is a Process
                    pobjectid = thing["pobjectid"]
                elif "process" in thing and thing["process"]:
                    # This is a NetworkConnection
                    pobjectid = thing["process"]["objectid"]
                else:
                    pobjectid = None

                if not pobjectid:
                    continue
                # We only want to sort if the thing has the same time observed as its parent
                if thing["objectid"]["time_observed"] != pobjectid["time_observed"]:
                    continue

                # If the parent object exists in the rest of the list
                for parent_index, parent in enumerate(things_to_sort_by_relationship[index+1:]):
                    if pobjectid["guid"] == parent["objectid"]["guid"] and pobjectid["time_observed"] == parent["objectid"]["time_observed"]:
                        popped_item = things_to_sort_by_relationship.pop(index+1+parent_index)
                        things_to_sort_by_relationship.insert(index, popped_item)
                        recurse_again = True
                        break
                if recurse_again:
                    break
        else:
            for index, thing in enumerate(things_to_sort_by_relationship[:]):
                # Confirm if we are working with an process or a network
                if hasattr(thing, "pobjectid"):
                    # This is a Process
                    pobjectid = thing.pobjectid
                elif hasattr(thing, "process") and thing.process:
                    # This is a NetworkConnection
                    pobjectid = thing.process.objectid
                else:
                    pobjectid = None

                if not pobjectid:
                    continue
                # We only want to sort if the thing has the same time observed as its parent
                if thing.objectid.time_observed != thing.pobjectid.time_observed:
                    continue
                # If the parent object exists in the rest of the list
                for parent_index, parent in enumerate(things_to_sort_by_relationship[index+1:]):
                    if thing.pobjectid.guid == parent.objectid.guid:
                        popped_item = things_to_sort_by_relationship.pop(index+1+parent_index)
                        things_to_sort_by_relationship.insert(index, popped_item)
                        recurse_again = True
                        break
                if recurse_again:
                    break

        if recurse_again:
            SandboxOntology ._sort_things_by_relationship(things_to_sort_by_relationship)
        return things_to_sort_by_relationship

    @staticmethod
    def _convert_events_to_dict(
        events: List[Union[Process, NetworkConnection]]
    ) -> Dict[str, Any]:
        """
        This method converts events to dictionaries
        :param events: A list of validated event objects
        :return: A dictionary representing the event objects
        """
        events_dict = {}

        if any([event.objectid.guid is None for event in events]):
            log.warning("All events must have a GUID at the ObjectID level...")
            return events_dict

        for event in events:
            events_dict[event.objectid.guid] = event.as_primitives()

        return events_dict

    @staticmethod
    def _convert_events_dict_to_tree(
        events_dict: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        This method converts a dictionary representing events into a tree by using pid/ppid or guid/pguid
        pairs for linking
        :param events_dict: A dictionary of events
        :return: A list of event tree roots, each which their respective branches and leaves
        """
        root = {
            "children": [],
        }
        sorted_events = SandboxOntology._sort_things_by_time_observed(
            list(events_dict.values())
        )
        try:
            # If events all have the same time observed, but there are child-parent relationships between events,
            # we should order based on relationship
            sorted_events_by_relationship_and_time = SandboxOntology._sort_things_by_relationship(
                sorted_events
            )
        except RecursionError:
            log.error("Unable to sort events by relationship due to recursion error.")
            sorted_events_by_relationship_and_time = sorted_events

        events_seen = []

        for e in sorted_events_by_relationship_and_time:
            if "children" not in e:
                e["children"] = []

            # This the main difference between Process and NetworkConnection
            pguid = None
            if "pobjectid" in e and e["pobjectid"]["guid"]:
                # This is a Process
                pguid = e["pobjectid"]["guid"]
            elif "process" in e and e["process"] and e["process"]["objectid"]["guid"]:
                # This is a NetworkConnection
                pguid = e["process"]["objectid"]["guid"]

            if pguid and pguid in events_seen:
                events_dict[pguid]["children"].append(e)
            else:
                root["children"].append(e)

            events_seen.append(e["objectid"]["guid"])

        return SandboxOntology._sort_things_by_time_observed(root["children"])

    def _convert_event_tree_to_result_section(
        self,
        items: List[ProcessItem],
        event: Dict[str, Any],
        safelist: List[str],
        result_section: ResultProcessTreeSection,
        parent: Optional[ProcessItem] = None,
    ) -> None:
        """
        This method converts the event tree into a ResultSection using recursion
        :param items: A list of ProcessItem objects
        :param event: A dictionary representing the Process to be converted
        :param safelist: A safelist of tree IDs that is to be applied to the events
        :param result_section: The Typed ResultSection for the Process (Event) Tree
        :param parent: The ProcessItem of the event to be converted
        :return: None
        """
        e = ProcessItem(
            pid=event["pid"],
            name=event["image"],
            cmd=event["command_line"],
        )
        e.add_network_events(len(self.get_network_connection_by_pid(e.pid)))
        # TODO
        # e.add_file_events(len(self.get_file_events_by_pid(e.pid)))
        # e.add_registry_events(len(self.get_registry_events_by_pid(e.pid)))

        if event["objectid"]["treeid"] in safelist:
            e.safelist()
        else:
            result_section.add_tag("dynamic.processtree_id", event["objectid"]["processtree"])

        for signature in self.get_signatures_by_pid(event["pid"]):
            e.add_signature(signature.name, signature.score)

        for child in event["children"][:]:
            # A telltale sign that the event is a NetworkConnection
            if "process" in child:
                # event is a NetworkConnection, we don't want this in the process tree result section, only the counts
                pass
            else:
                self._convert_event_tree_to_result_section(items, child, safelist, result_section, parent=e)
            event["children"].remove(child)

        if not event["children"] and not parent:
            items.append(e)
        elif not event["children"] and parent:
            parent.add_child_process(e)

    def _create_hashed_node(
        self, parent_treeid: str, parent_processtree: str, node: Dict[str, Any]
    ) -> None:
        """
        This method takes a single node and hashes node attributes.
        Recurses through children to do the same.
        :param parent_treeid: A string representing the tree id
        :param parent_processtree: A string representing the rich id
        :param node: A dictionary representing the node to hash
        :return: None
        """
        children = node["children"]

        tag = node["objectid"].get("tag", "notag")
        value_to_create_hash_from = (parent_treeid + tag).encode()
        sha256sum = sha256(value_to_create_hash_from).hexdigest()
        node["objectid"]["treeid"] = sha256sum

        if parent_processtree:
            processtree = f"{parent_processtree}|{tag}"
        elif node.get("pobjectid", {}).get("processtree"):
            processtree = f"{node['pobjectid']['processtree']}|{tag}"
        elif node.get("pobjectid", {}).get("tag"):
            processtree = f"{node['pobjectid']['tag']}|{tag}"
        else:
            processtree = tag
        node["objectid"]["processtree"] = processtree

        if node["objectid"].get("guid"):
            self.update_objectid(
                guid=node["objectid"]["guid"], treeid=sha256sum, processtree=processtree
            )

        for child in children:
            self._create_hashed_node(sha256sum, processtree, child)

    def _create_treeids(self, process_tree: List[Dict[str, Any]]) -> None:
        """
        This method creates tree IDs for each node in the process tree
        :param process_tree: A list of dictionaries where each dictionary represents a root.
        :return: None
        """
        for root in process_tree:
            self._create_hashed_node("", "", root)

    @staticmethod
    def _remove_safe_leaves_helper(
        node: Dict[str, Any], safe_treeids: List[str]
    ) -> Union[str, None]:
        """
        This method is used to recursively remove safe branches from the given node. It removes a branch from the leaf
        up until it is reaches a node that is not safelisted
        :param node: A dictionary of a process tree node (root)
        :param safe_treeids: All of the safe leaf tree IDs (the safelist)
        :return: Returns the string representing the node's hash for the purpose of recursive removal,
                 or returns None if the removal is complete
        """
        children: List[Dict[str, Any]] = node["children"]
        num_removed = 0
        len_of_children = len(children)
        for index in range(len_of_children):
            child_to_operate_on = children[index - num_removed]
            hash_to_remove = SandboxOntology._remove_safe_leaves_helper(
                child_to_operate_on, safe_treeids
            )
            if (
                hash_to_remove
                and hash_to_remove == child_to_operate_on["objectid"]["treeid"]
            ):
                children.remove(child_to_operate_on)
                num_removed += 1
                # We need to overwrite the hash of the parent node with the hash to remove to that it will be
                # removed from the tree as well.
                if not children:
                    node["objectid"]["treeid"] = hash_to_remove

        if not children:
            treeid = node["objectid"]["treeid"]
            if treeid in safe_treeids:
                return treeid
            else:
                return None

    @staticmethod
    def _remove_safe_leaves(
        process_tree: List[Dict[str, Any]], safe_treeids: List[str]
    ) -> None:
        """
        This method checks each leaf's hash against the safe tree IDs and removes safe branches from the process tree
        :param process_tree: A list of dictionaries where each dictionary represents a root.
        :param safe_treeids: A list containing the tree IDs of each safe branch
        :return: None
        """
        for root in process_tree[:]:
            _ = SandboxOntology._remove_safe_leaves_helper(root, safe_treeids)
            if root["objectid"]["treeid"] in safe_treeids and not root["children"]:
                process_tree.remove(root)

    @staticmethod
    def _filter_event_tree_against_safe_treeids(
        event_tree: List[Dict[str, Any]], safe_treeids: List[str]
    ) -> List[Dict[str, Any]]:
        """
        This method takes an event tree and a list of safe process tree tree IDs, and filters out safe process roots
        in the tree.
        :param event_tree: A list of processes in a tree structure
        :param safe_treeids: A List of tree IDs representing safe leaf nodes/branches
        :return: A list of processes in a tree structure, with the safe branches filtered out
        """
        SandboxOntology._remove_safe_leaves(event_tree, safe_treeids)
        return event_tree

    @staticmethod
    def _validate_artifacts(
        artifact_list: List[Dict[str, Any]] = None
    ) -> List[Artifact]:
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
                to_be_extracted=artifact["to_be_extracted"],
            )
            validated_artifacts.append(validated_artifact)
        return validated_artifacts

    @staticmethod
    def _handle_artifact(
        artifact: Artifact = None, artifacts_result_section: ResultSection = None
    ) -> None:
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
                    (
                        subsection
                        for subsection in artifacts_result_section.subsections
                        if subsection.title_text == HOLLOWSHUNTER_TITLE
                    ),
                    None,
                )

                if artifact_result_section is None:
                    artifact_result_section = ResultSection(HOLLOWSHUNTER_TITLE)
                    artifact_result_section.set_heuristic(17)
                    artifact_result_section.add_line(
                        "HollowsHunter dumped the following:"
                    )

                artifact_result_section.add_line(f"\t- {artifact.name}")
                artifact_result_section.add_tag(
                    "dynamic.process.file_name", artifact.name
                )
                # As of right now, heuristic ID 17 is associated with the Injection category in the Cuckoo service
                if regex in [HOLLOWSHUNTER_EXE_REGEX]:
                    artifact_result_section.heuristic.add_signature_id(
                        "hollowshunter_exe"
                    )
                elif regex in [HOLLOWSHUNTER_DLL_REGEX]:
                    artifact_result_section.heuristic.add_signature_id(
                        "hollowshunter_dll"
                    )

        if (
            artifact_result_section is not None
            and artifact_result_section not in artifacts_result_section.subsections
        ):
            artifacts_result_section.add_subsection(artifact_result_section)

    def _set_item_times(self, item: Union[Process, ObjectID]) -> None:
        """
        This method sets the item times to values that the ODM can handle
        :param item: An item, either a Process or an ObjectID, whose times will be validated
        :return: None
        """
        if item is None:
            return
        if isinstance(item, Process):
            if item.start_time == float("-inf"):
                item.set_start_time(self.analysis_metadata.start_time)
            if item.end_time == float("inf"):
                item.set_end_time(self.analysis_metadata.end_time)
            if item.objectid.time_observed == float("-inf"):
                item.objectid.set_time_observed(self.analysis_metadata.start_time)
            if item.objectid.time_observed == float("inf"):
                item.objectid.set_time_observed(self.analysis_metadata.end_time)
        elif isinstance(item, ObjectID):
            if item.time_observed == float("-inf"):
                item.set_time_observed(self.analysis_metadata.start_time)
            if item.time_observed == float("inf"):
                item.set_time_observed(self.analysis_metadata.end_time)
        else:
            log.warning(f"Given object {item} is neither Process or ObjectID...")

    def _remove_safelisted_processes(self, safelist: List[str]) -> None:
        """
        This method removes all safelisted processes and all activities associated with those processes
        :return: None
        """
        safelisted_processes = [process for process in self.get_processes() if process.objectid.treeid in safelist]
        safelisted_network_http = [http for http in self.get_network_http()
                                   if http.connection_details.process in safelisted_processes]
        safelisted_network_dns = [dns for dns in self.get_network_dns()
                                  if dns.connection_details.process in safelisted_processes]
        safelisted_network_connections = [nc for nc in self.get_network_connections()
                                          if nc.process in safelisted_processes]
        safelisted_signatures = [sig for sig in self.get_signatures() if sig.process in safelisted_processes]
        # TODO Somehow get safelisted subjects
        # safelisted_signatures = [sig for sig in self.get_signatures() if sig.process in safelisted_processes]
        for safelisted_http in safelisted_network_http:
            self._remove_network_http(safelisted_http)
        for safelisted_dns in safelisted_network_dns:
            self._remove_network_dns(safelisted_dns)
        for safelisted_conn in safelisted_network_connections:
            self._remove_network_connection(safelisted_conn)
        for safelisted_signature in safelisted_signatures:
            self._remove_signature(safelisted_signature)
        for safelisted_process in safelisted_processes:
            self._remove_process(safelisted_process)

    def preprocess_ontology(self, safelist: List[str] = None, from_main: bool = False, so_json: str = None) -> None:
        """
        This method preprocesses the ontology before it gets validated by Assemblyline's base ODM
        :param from_main: A boolean flag that indicates if this method is being run from __main__
        :param so_json: The path to the json file that represents the Sandbox Ontology
        :return: None
        """
        if safelist is None:
            safelist: List[str] = []

        # DEBUGGING case
        if from_main:
            from assemblyline.odm.models.ontology.types.sandbox import Sandbox
            from json import loads

            with open(so_json, "r") as f:
                file_contents = loads(f.read())

            self.load_from_json(file_contents)
            for process in self.get_processes():
                self._set_item_times(process)

            for signature in self.get_signatures():
                self._set_item_times(signature.process)
                for subject in signature.get_subjects():
                    self._set_item_times(subject.process)

            for network_connection in self.get_network_connections():
                self._set_item_times(network_connection.process)

            for dns in self.get_network_dns():
                self._set_item_times(dns.connection_details.process)

            for http in self.get_network_http():
                self._set_item_times(http.connection_details.process)

            self._remove_safelisted_processes(safelist)

            Sandbox(
                data=self.as_primitives(), ignore_extra_values=False
            ).as_primitives()
        # Service runtime case
        else:
            self._remove_safelisted_processes(safelist)

            for process in self.get_processes():
                self._set_item_times(process)

            for signature in self.get_signatures():
                self._set_item_times(signature.process)
                for subject in signature.get_subjects():
                    self._set_item_times(subject.process)

            for network_connection in self.get_network_connections():
                self._set_item_times(network_connection.process)

            for dns in self.get_network_dns():
                self._set_item_times(dns.connection_details.process)

            for http in self.get_network_http():
                self._set_item_times(http.connection_details.process)


def extract_iocs_from_text_blob(
        blob: str, result_section: ResultTableSection, so_sig: SandboxOntology.Signature = None) -> None:
    """
    This method searches for domains, IPs and URIs used in blobs of text and tags them
    :param blob: The blob of text that we will be searching through
    :param result_section: The result section that that tags will be added to
    :param so_sig: The signature for the Sandbox Ontology
    :return: None
    """
    if not blob:
        return
    blob = blob.lower()
    ips = set(findall(IP_REGEX, blob))
    # There is overlap here between regular expressions, so we want to isolate domains that are not ips
    domains = set(findall(DOMAIN_REGEX, blob)) - ips
    # There is overlap here between regular expressions, so we want to isolate uris that are not domains
    # TODO: Are we missing IOCs to the point where we need a different regex?
    # uris = {uri.decode() for uri in set(findall(PatternMatch.PAT_URI_NO_PROTOCOL, blob.encode()))} - domains - ips
    uris = set(findall(URL_REGEX, blob)) - domains - ips
    for ip in ips:
        if add_tag(result_section, "network.dynamic.ip", ip):
            if not result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="ip", ioc=ip))
            elif dumps({"ioc_type": "ip", "ioc": ip}) not in result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="ip", ioc=ip))
            if so_sig:
                so_sig.add_subject(ip=ip)
    for domain in domains:
        # File names match the domain and URI regexes, so we need to avoid tagging them
        # Note that get_tld only takes URLs so we will prepend http:// to the domain to work around this
        if add_tag(result_section, "network.dynamic.domain", domain):
            if not result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="domain", ioc=domain))
            elif dumps({"ioc_type": "domain", "ioc": domain}) not in result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="domain", ioc=domain))
            if so_sig:
                so_sig.add_subject(domain=domain)

    for uri in uris:
        if add_tag(result_section, "network.dynamic.uri", uri):
            if not result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="uri", ioc=uri))
            elif dumps({"ioc_type": "uri", "ioc": uri}) not in result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="uri", ioc=uri))
            if so_sig:
                so_sig.add_subject(uri=uri)
        if "//" in uri:
            uri = uri.split("//")[1]
        for uri_path in findall(URI_PATH, uri):
            if add_tag(result_section, "network.dynamic.uri_path", uri_path):
                if not result_section.section_body.body:
                    result_section.add_row(TableRow(ioc_type="uri_path", ioc=uri_path))
                elif dumps({"ioc_type": "uri_path", "ioc": uri_path}) not in result_section.section_body.body:
                    result_section.add_row(TableRow(ioc_type="uri_path", ioc=uri_path))


# DEBUGGING METHOD
if __name__ == "__main__":
    # This method is for validating the output from the SandboxOntology class -> Sandbox class
    from sys import argv

    so_json_path = argv[1]
    default_so = SandboxOntology()
    default_so.preprocess_ontology(safelist=[], from_main=True, so_json=so_json_path)
