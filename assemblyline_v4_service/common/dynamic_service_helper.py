from datetime import datetime
from hashlib import sha256
from json import dumps
from logging import getLogger
from re import compile, escape, sub, findall, match as re_match
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from assemblyline.common import log as al_log
from assemblyline.common.attack_map import (
    attack_map,
    software_map,
    group_map,
    revoke_map,
)
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.isotime import (
    epoch_to_local,
    LOCAL_FMT,
    local_to_epoch,
    MAX_TIME,
    MIN_TIME,
    format_time,
)
from assemblyline.common.uid import get_random_id
from assemblyline.odm.base import DOMAIN_REGEX, IP_REGEX, FULL_URI, URI_PATH
from assemblyline.odm.models.ontology.results import (
    Process as ProcessModel, Sandbox as SandboxModel,
    Signature as SignatureModel,
    NetworkConnection as NetworkConnectionModel
)

# from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    ResultSection,
    ProcessItem,
    ResultProcessTreeSection,
    ResultTableSection,
    TableRow,
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
WINDIR_ENV_VARIABLE = "%windir%"
SAMPLEPATH_ENV_VARIABLE = "%samplepath%"
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

MIN_DOMAIN_CHARS = 8
# Choosing an arbitrary number, based on https://webmasters.stackexchange.com/questions/16996/maximum-domain-name-length
MAX_DOMAIN_CHARS = 100
MIN_URI_CHARS = 11
MIN_URI_PATH_CHARS = 4

# There are samples that inject themselves for the entire analysis time
# and have the potential to exceed depths of 1000. Also, the assumption with 10 is that no process
# tree would be that complex and useful at the same time.
PROCESS_TREE_DEPTH_LIMIT = 10
OBJECTID_KEYS = [
    "tag",
    "ontology_id",
    "service_name",
    "guid",
    "treeid",
    "processtree",
    "time_observed",
    "session",
]
POBJECTID_KEYS = [
    "ptag",
    "pontology_id",
    "pservice_name",
    "pguid",
    "ptreeid",
    "pprocesstree",
    "ptime_observed",
    "psession",
    "ontology_id",
    "service_name",
]

MAX_TIME = format_time(MAX_TIME, LOCAL_FMT)
MIN_TIME = format_time(MIN_TIME, LOCAL_FMT)

SERVICE_NAME = None


def set_required_argument(self: object, name: str, value: Any, value_type: Any) -> None:
    """
    This method performs validation of a value that is to be set to an object attribute
    :param self: The object whose attribute will be set
    :param name: The name of the attribute
    :param value: The value to be set
    :param value_type: The type that the value should be
    :return: None
    """
    if not value:
        raise ValueError(f"{name} must have a legitimate value")
    elif not isinstance(value, value_type):
        raise TypeError(f"{name} must be a {value_type}")
    else:
        setattr(self, name, value)


def set_optional_argument(self, name: str, value: Any, value_type: Any) -> None:
    """
    This method performs validation of an optional value that is to be set to an object attribute
    :param self: The object whose attribute will be set
    :param name: The name of the attribute
    :param value: The value to be set
    :param value_type: The type that the value should be
    :return: None
    """
    if value is not None and not value:
        raise ValueError(f"{name} must have a legitimate value")
    elif value and not isinstance(value, value_type):
        raise TypeError(f"{name} must be a {value_type}")
    else:
        setattr(self, name, value)


def update_object_items(self: object, update_items: Dict[str, Any]) -> None:
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
        if hasattr(self, key) and getattr(self, key) not in [
            "",
            None,
            [],
            {},
            (),
            MAX_TIME,
            MIN_TIME,
        ]:
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
        sha256: str = None,
    ):
        """
        This method initializes an artifact object
        :param name: The name of the artifact
        :param path: The path of the artifact
        :param description: The description of the artifact
        :param to_be_extracted: A flag indicating if the artifact should be extracted or added as a supplementary file
        :param sha256: The SHA256 hash of the artifact's contents
        """
        if any(item is None for item in [name, path, description, to_be_extracted]):
            raise Exception("Missing positional arguments for Artifact validation")

        self.name = name
        self.path = path
        self.description = description
        self.to_be_extracted = to_be_extracted
        self.sha256 = sha256

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {key: value for key, value in self.__dict__.items()}


class ObjectID:
    def __init__(
        self,
        tag: str,
        ontology_id: str,
        service_name: Optional[str] = None,
        guid: Optional[str] = None,
        treeid: Optional[str] = None,
        processtree: Optional[str] = None,
        time_observed: Optional[str] = None,
        session: Optional[str] = None,
    ) -> None:
        """
        This method initializes the characteristics used to identify an object
        :param tag: The normalized tag of the object
        :param ontology_id: Unique identifier of ontology
        :param service_name: Component that generated this section
        :param guid: The GUID associated with the object
        :param treeid: The hash of the tree ID
        :param processtree: Human-readable tree ID (concatenation of tags)
        :param time_observed: The time at which the object was observed
        :param session: Unifying session name/ID
        :return: None
        """
        set_required_argument(self, "tag", tag, str)
        set_required_argument(self, "ontology_id", ontology_id, str)

        set_optional_argument(self, "service_name", service_name, str)
        if not self.service_name and SERVICE_NAME is None:
            raise ValueError("The service_name must be set")
        elif not self.service_name and SERVICE_NAME:
            self.service_name = SERVICE_NAME

        set_optional_argument(self, "guid", guid, str)
        if self.guid:
            # Enforce this format for all given guids
            self.guid = f"{{{str(UUID(guid)).upper()}}}"

        set_optional_argument(self, "treeid", treeid, str)
        set_optional_argument(self, "processtree", processtree, str)
        set_optional_argument(self, "time_observed", time_observed, str)
        set_optional_argument(self, "session", session, str)

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

    def set_time_observed(self, time_observed: str) -> None:
        """
        This method updates the time_observed for the ObjectID
        :param time_observed: The time_observed of the ObjectID
        :return: None
        """
        if not time_observed:
            raise ValueError("time_observed must have a legitimate value")
        elif time_observed and not isinstance(time_observed, str):
            raise TypeError("time_observed must be a str")
        else:
            if "." in time_observed:
                time_observed = time_observed[:time_observed.index(".")]
            self.time_observed = str(datetime.strptime(time_observed, LOCAL_FMT))


class Process:
    def __init__(
        self,
        objectid: ObjectID,
        image: str,
        start_time: Optional[str] = None,
        pobjectid: Optional[ObjectID] = None,
        pimage: Optional[str] = None,
        pcommand_line: Optional[str] = None,
        ppid: Optional[int] = None,
        pid: Optional[int] = None,
        command_line: Optional[str] = None,
        end_time: Optional[str] = None,
        integrity_level: Optional[str] = None,
        image_hash: Optional[str] = None,
        original_file_name: Optional[str] = None,
    ) -> None:
        """
        This method initializes a process object
        :param objectid: The object ID of the process object
        :param image: The image of the process
        :param start_time: The time of creation for the process
        :param pobjectid: The object ID of the parent process object
        :param pimage: The image of the parent process that spawned this process
        :param pcommand_line: The command line that the parent process ran
        :param ppid: The process ID of the parent process
        :param pid: The process ID
        :param command_line: The command line that the process ran
        :param end_time: The time of termination for the process
        :param integrity_level: The integrity level of the process
        :param image_hash: The hash of the file run
        :param original_file_name: The original name of the file
        :return: None
        """
        if (
            start_time
            and end_time
            and local_to_epoch(start_time) > local_to_epoch(end_time)
        ):
            raise ValueError(
                f"Start time {start_time} cannot be greater than end time {end_time}."
            )

        if pid and ppid and pid == ppid:
            raise ValueError(f"PID {pid} cannot be equal to its PPID")

        set_required_argument(self, "objectid", objectid, ObjectID)
        set_required_argument(self, "image", image, str)
        set_optional_argument(self, "start_time", start_time, str)
        if self.objectid and self.start_time and self.objectid.time_observed is None:
            self.objectid.time_observed = self.start_time

        # Parent process details
        set_optional_argument(self, "pobjectid", pobjectid, ObjectID)
        set_optional_argument(self, "pimage", pimage, str)
        set_optional_argument(self, "pcommand_line", pcommand_line, str)
        set_optional_argument(self, "ppid", ppid, int)

        set_optional_argument(self, "pid", pid, int)
        set_optional_argument(self, "command_line", command_line, str)
        set_optional_argument(self, "end_time", end_time, str)

        set_optional_argument(self, "integrity_level", integrity_level, str)
        if self.integrity_level:
            self.integrity_level = self.integrity_level.lower()

        set_optional_argument(self, "image_hash", image_hash, str)
        set_optional_argument(self, "original_file_name", original_file_name, str)

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
        if all(value is None for value in kwargs.values()):
            return

        if "objectid" in kwargs:
            objectid = kwargs.pop("objectid")
            if objectid and isinstance(objectid, ObjectID):
                self.update_objectid(**objectid.as_primitives())
            elif isinstance(objectid, Dict):
                self.update_objectid(**objectid)

        if "pobjectid" in kwargs:
            pobjectid = kwargs.pop("pobjectid")
            if pobjectid and isinstance(pobjectid, ObjectID):
                self.update_pobjectid(**pobjectid.as_primitives())
            elif isinstance(pobjectid, Dict):
                self.update_pobjectid(**pobjectid)

        if "start_time" in kwargs and self.objectid.time_observed is None:
            self.objectid.set_time_observed(kwargs["start_time"])

        if "integrity_level" in kwargs and isinstance(kwargs["integrity_level"], str):
            kwargs["integrity_level"] = kwargs["integrity_level"].lower()

        # Remove objectid attributes
        kwargs = {
            key: value
            for key, value in kwargs.items()
            if key not in OBJECTID_KEYS and key not in POBJECTID_KEYS
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

    def set_start_time(self, start_time: str) -> None:
        """
        This method updates the start time for the Process
        :param start_time: The start time of the Process
        :return: None
        """
        self.start_time = start_time

    def set_end_time(self, end_time: str) -> None:
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
        self.objectid.set_tag(Process.create_objectid_tag(image))

    @staticmethod
    def create_objectid_tag(image: Optional[str]) -> Optional[str]:
        """
        This method normalizes the image path and creates the objectid tag
        :return: None
        """
        if not image:
            return

        return Process._normalize_path(image)

    def set_pobjectid_tag(self, image: Optional[str]) -> None:
        """
        This method normalizes the image path and sets the pobjectid tag
        :return: None
        """
        if not image:
            return
        if not self.pobjectid:
            log.debug("You need to set pobjectid before setting its tag")
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

        if (
            not self.pobjectid
            and kwargs.get("tag")
            and kwargs.get("ontology_id")
            and kwargs.get("service_name")
        ):
            self.pobjectid: ObjectID = ObjectID(
                kwargs["tag"], kwargs["ontology_id"], kwargs["service_name"]
            )
        elif not self.pobjectid:
            log.debug("You need to set pobjectid or pass its required arguments")
            return

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
        rules.append({"pattern": WINDIR_ENV_VARIABLE, "replacement": "?win"})
        rules.append({"pattern": SAMPLEPATH_ENV_VARIABLE, "replacement": "?usrtmp"})
        for rule in rules:
            if "pattern" in rule:
                path = Process._pattern_substitution(path, rule)
            if "regex" in rule:
                path = Process._regex_substitution(path, rule)
        return path


class NetworkDNS:
    def __init__(
        self,
        domain: str,
        resolved_ips: List[str],
        lookup_type: str,
    ) -> None:
        """
        Details for a DNS request
        :param domain: The domain requested
        :param resolved_ips: A list of IPs that were resolved
        :param lookup_type: The type of DNS request
        :return: None
        """
        set_required_argument(self, "domain", domain, str)
        set_required_argument(self, "resolved_ips", resolved_ips, List)
        set_required_argument(self, "lookup_type", lookup_type, str)

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {key: value for key, value in self.__dict__.items()}


class NetworkHTTP:
    def __init__(
        self,
        request_uri: str,
        request_method: str,
        request_headers: Optional[Dict[str, str]] = None,
        response_headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None,
        response_status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        request_body_path: Optional[str] = None,
        response_body_path: Optional[str] = None,
    ) -> None:
        """
        Details for an HTTP request
        :param request_uri: The URI requested
        :param request_method: The method of the request
        :param request_headers: Headers included in the request
        :param response_headers: The headers of the response
        :param request_body: The body of the request
        :param response_status_code: The status code of the response
        :param response_body: The body of the response
        :param request_body_path: The path to the file containing the request body
        :param response_body_path: The path to the file containing the response body
        :return: None
        """
        set_required_argument(self, "request_uri", request_uri, str)
        set_required_argument(self, "request_method", request_method, str)

        set_optional_argument(self, "request_headers", request_headers, Dict)
        if not self.request_headers:
            self.request_headers: Dict[str, str] = {}

        set_optional_argument(self, "response_headers", response_headers, Dict)
        if not self.response_headers:
            self.response_headers: Dict[str, str] = {}

        set_optional_argument(self, "request_body", request_body, str)
        set_optional_argument(self, "response_status_code", response_status_code, int)
        set_optional_argument(self, "response_body", response_body, str)
        set_optional_argument(self, "request_body_path", request_body_path, str)
        set_optional_argument(self, "response_body_path", response_body_path, str)

    def update(self, **kwargs) -> None:
        """
        This method updates networkhttp attributes with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the networkhttp attributes
        :return: None
        """
        if all(value is None for value in kwargs.values()):
            return
        update_object_items(self, kwargs)

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {
            key: value
            for key, value in self.__dict__.items()
            if key not in ["request_body_path", "response_body_path"]
        }


class NetworkConnection:
    OUTBOUND = "outbound"
    INBOUND = "inbound"
    UNKNOWN = "unknown"
    DIRECTIONS = [OUTBOUND, INBOUND, UNKNOWN]
    TCP = "tcp"
    UDP = "udp"
    TRANSPORT_LAYER_PROTOCOL = [TCP, UDP]
    HTTP = "http"
    DNS = "dns"
    CONNECTION_TYPES = [HTTP, DNS]

    def __init__(
        self,
        objectid: ObjectID,
        destination_ip: str,
        destination_port: int,
        transport_layer_protocol: str,
        direction: str,
        process: Optional[Process] = None,
        source_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        http_details: Optional[NetworkHTTP] = None,
        dns_details: Optional[NetworkDNS] = None,
        connection_type: Optional[str] = None,
    ) -> None:
        """
        Details for a low-level network connection by IP
        :param objectid: The object ID of the network object
        :param destination_ip: The destination IP of the connection
        :param destination_port: The destination port of the connection
        :param transport_layer_protocol: The transport layer protocol of the connection
        :param direction: The direction of the network connection
        :param process: The process that spawned the network connection
        :param source_ip: The source IP of the connection
        :param source_port: The source port of the connection
        :param http_details: HTTP-specific details of request
        :param dns_details: DNS-specific details of request
        :param connection_type: Type of connection being made
        :return: None
        """
        if transport_layer_protocol not in self.TRANSPORT_LAYER_PROTOCOL:
            raise ValueError(
                f"Invalid transport layer protocol: {transport_layer_protocol}"
            )

        if direction not in self.DIRECTIONS:
            raise ValueError(f"Invalid direction: {direction}")

        set_required_argument(self, "objectid", objectid, ObjectID)
        set_required_argument(self, "destination_ip", destination_ip, str)
        set_required_argument(self, "destination_port", destination_port, int)
        set_required_argument(
            self, "transport_layer_protocol", transport_layer_protocol, str
        )
        set_required_argument(self, "direction", direction, str)

        set_optional_argument(self, "process", process, Process)
        set_optional_argument(self, "source_ip", source_ip, str)
        set_optional_argument(self, "source_port", source_port, int)
        set_optional_argument(self, "http_details", http_details, NetworkHTTP)
        set_optional_argument(self, "dns_details", dns_details, NetworkDNS)
        if self.http_details and self.dns_details:
            raise ValueError(
                "A network connection cannot be associated to both a DNS and an HTTP call."
            )
        set_optional_argument(self, "connection_type", connection_type, str)
        if self.connection_type:
            if self.connection_type not in self.CONNECTION_TYPES:
                raise ValueError(
                    f"Connection type {self.connection_type} must be one of {self.CONNECTION_TYPES}"
                )
            elif self.connection_type == self.HTTP and self.http_details is None:
                raise ValueError(
                    f"Connection type is {self.HTTP} but {self.HTTP}_details is None"
                )
            elif self.connection_type == self.DNS and self.dns_details is None:
                raise ValueError(
                    f"Connection type is {self.DNS} but {self.DNS}_details is None"
                )
        else:
            if self.http_details or self.dns_details:
                raise ValueError("Specify the connection type")

    def update_objectid(self, **kwargs) -> None:
        """
        This method updates the network connection objectid attributes with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the network connection objectid attributes
        :return: None
        """
        if all(value is None for value in kwargs.values()):
            return
        update_object_items(self.objectid, kwargs)

    def update(self, **kwargs) -> None:
        """
        This method updates attributes with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating attributes
        :return: None
        """
        if all(value is None for value in kwargs.values()):
            return

        if "objectid" in kwargs:
            objectid = kwargs.pop("objectid")
            if objectid and isinstance(objectid, ObjectID):
                self.update_objectid(**objectid.as_primitives())
            elif objectid and isinstance(objectid, Dict):
                self.update_objectid(**objectid)
        else:
            # Get the objectid attributes out
            objectid_kwargs = {
                key: value for key, value in kwargs.items() if key in OBJECTID_KEYS
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
            key: value for key, value in kwargs.items() if key not in OBJECTID_KEYS
        }
        update_object_items(self, kwargs)

    def update_process(self, **kwargs) -> None:
        """
        This method updates the process object attribute with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the process object attribute
        :return: None
        """
        if (
            not self.process
            and kwargs.get("objectid")
            and kwargs.get("image")
            and kwargs.get("start_time")
        ):
            self.process: Process = Process(
                kwargs["objectid"], kwargs["image"], kwargs["start_time"]
            )
        elif not self.process:
            log.debug("You need to set process or pass its required arguments")
            return
        self.process.update(**kwargs)

    def update_process_objectid(self, **kwargs) -> None:
        """
        This method updates the process ObjectID with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the process object attribute
        :return: None
        """
        if not self.process:
            raise ValueError(
                "Process must be set before you can update the process ObjectID"
            )
        self.process.update_objectid(**kwargs)

    def set_process(self, process: Process) -> None:
        """
        This method sets the process object attribute to the given process
        :param process: The given process object
        :return: None
        """
        self.process = process

    @staticmethod
    def create_tag(
        destination_ip: Optional[str] = None,
        destination_port: Optional[int] = None,
        domain: Optional[str] = None,
        direction: Optional[str] = None,
    ) -> Optional[str]:
        """
        This method creates the tag object for a network connection
        :param destination_ip: The destination IP of the connection
        :param destination_port: The destination port of the connection
        :param domain: The domain associated with the destination IP used in this network connection
        :param direction: The direction of the network connection
        :return: The created tag, if any
        """
        if not domain and destination_ip is None:
            log.debug(
                "Cannot set tag for network connection. Requires either domain or destination IP..."
            )
            return
        if destination_port is None:
            log.debug(
                "Cannot set tag for network connection. Requires destination port..."
            )
            return

        if domain and direction == NetworkConnection.OUTBOUND:
            return f"{domain}:{destination_port}"
        # If no domain or if direction is inbound/unknown
        else:
            return f"{destination_ip}:{destination_port}"

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {
            key: value
            if (
                not isinstance(value, Process)
                and not isinstance(value, ObjectID)
                and not isinstance(value, NetworkDNS)
                and not isinstance(value, NetworkHTTP)
            )
            else value.as_primitives()
            for key, value in self.__dict__.items()
        }


class Attribute:

    actions = [
        "clipboard_capture",
        "create_remote_thread",
        "create_stream_hash",
        "dns_query",
        "driver_loaded",
        "file_change",
        "file_creation",
        "file_delete",
        "image_loaded",
        "network_connection",
        "network_connection_linux",
        "pipe_created",
        "process_access",
        "process_creation",
        "process_creation_linux",
        "process_tampering",
        "process_terminated",
        "raw_access_thread",
        "registry_add",
        "registry_delete",
        "registry_event",
        "registry_rename",
        "registry_set",
        "sysmon_error",
        "sysmon_status",
        "wmi_event",
    ]

    def __init__(
        self,
        source: ObjectID,
        target: Optional[ObjectID] = None,
        action: Optional[str] = None,
        meta: Optional[str] = None,
        event_record_id: Optional[str] = None,
        domain: Optional[str] = None,
        uri: Optional[str] = None,
        file_hash: Optional[str] = None,
    ) -> None:
        """
        Attribute relating to the signature that was raised during the analysis of the task
        :param source: Object that the rule triggered on
        :param target: Object targetted by source object
        :param action: The relation between the source and target
        :param meta: Metadata about the detection
        :param event_record_id: Event Record ID (Event Logs)
        :param domain: Domain
        :param uri: URI
        :param file_hash: SHA256 of file
        :return: None
        """
        set_required_argument(self, "source", source, ObjectID)
        set_optional_argument(self, "target", target, ObjectID)

        set_optional_argument(self, "action", action, str)
        if self.action and self.action not in self.actions:
            raise ValueError(
                f"The action {self.action} is not in the list of valid actions"
            )

        set_optional_argument(self, "meta", meta, str)
        set_optional_argument(self, "event_record_id", event_record_id, str)
        set_optional_argument(self, "domain", domain, str)
        set_optional_argument(self, "uri", uri, str)
        set_optional_argument(self, "file_hash", file_hash, str)

    def update(self, **kwargs) -> None:
        """
        This method updates the attribute object with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the attribute object
        :return: None
        """
        update_object_items(self, kwargs)

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {
            key: value if not isinstance(value, ObjectID) else value.as_primitives()
            for key, value in self.__dict__.items()
        }


class Signature:
    types = ["CUCKOO", "YARA", "SIGMA", "SURICATA"]

    def __init__(
        self,
        objectid: ObjectID,
        name: str,
        type: str,
        attributes: Optional[List[Attribute]] = None,
        attacks: Optional[List[Dict[str, Any]]] = None,
        actors: Optional[List[str]] = None,
        malware_families: Optional[List[str]] = None,
        score: Optional[int] = None,
    ) -> None:
        """
        A signature that was raised during the analysis of the task
        :param objectid: The object ID of the signature object
        :param name: The name of the signature
        :param type: Type of signature
        :param attributes: Attributes about the signature
        :param attacks: A list of ATT&CK patterns and categories of the signature
        :param actors: List of actors of the signature
        :param malware_families: List of malware families of the signature
        :param score: Score of the signature
        :return: None
        """
        set_required_argument(self, "objectid", objectid, ObjectID)
        set_required_argument(self, "name", name, str)
        set_required_argument(self, "type", type, str)
        if self.type not in self.types:
            raise ValueError(f"The type {self.type} is not a valid type")

        set_optional_argument(self, "attributes", attributes, List)
        if not self.attributes:
            self.attributes: List[Attribute] = []

        set_optional_argument(self, "attacks", attacks, List)
        if not self.attacks:
            self.attacks: List[Dict[str, Any]] = []

        set_optional_argument(self, "actors", actors, List)
        if not self.actors:
            self.actors: List[str] = []

        set_optional_argument(self, "malware_families", malware_families, List)
        if not self.malware_families:
            self.malware_families: List[str] = []

        set_optional_argument(self, "score", score, int)

    def update(self, **kwargs) -> None:
        """
        This method updates the signature object with the given keyword arguments
        :param kwargs: Key word arguments to be used for updating the signature object
        :return: None
        """
        update_object_items(self, kwargs)

    def add_attack_id(self, attack_id: str) -> None:
        """
        This method adds an Att&ck ID to the signature's list of Att&ck IDs
        :param attack_id: The Att&ck ID to add
        :return: None
        """
        attack_item = None
        attack_id = revoke_map.get(attack_id, attack_id)
        current_attack_ids = [a["attack_id"] for a in self.attacks]
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
            self.attacks.append(attack_item)
        else:
            log.warning(f"Could not generate Att&ck output for ID: {attack_id}")

    @staticmethod
    def create_attribute(**kwargs) -> Optional[Attribute]:
        """
        This method creates an Attribute, assigns its attributes based on keyword arguments provided,
        and returns the Attribute
        :param kwargs: Key word arguments to be used for updating the Attribute's attributes
        :return: Attribute object
        """
        # We want to perform this backend check for Attribute kwargs since they have a high degree of variability
        if all(value is None for value in kwargs.values()):
            return

        if not kwargs.get("source"):
            raise ValueError("The attribute needs its required arguments")
        elif not isinstance(kwargs["source"], ObjectID):
            raise ValueError("source is not an ObjectID")

        attribute = Attribute(source=kwargs["source"])
        update_object_items(attribute, kwargs)
        return attribute

    def add_attribute(self, attribute: Attribute) -> None:
        """
        This method adds an attribute to the list of attributes for the signature.
        :param attribute: The attribute to be added
        :return: None
        """
        if any(
            attribute.as_primitives() == added_attribute.as_primitives()
            for added_attribute in self.attributes
        ):
            return

        self.attributes.append(attribute)

    def get_attributes(self) -> List[Attribute]:
        """
        This method returns the attributes associated with the signature
        :return: The list of attributes associated with the signature
        """
        return self.attributes

    def set_score(self, score: int) -> None:
        """
        This method sets the signature score
        :param score: The score to set
        :return: None
        """
        self.score: int = score

    def set_malware_families(self, malware_families: List[str]) -> None:
        """
        This method sets the signature malware families
        :param malware_families: The malware families to set
        :return: None
        """
        self.malware_families: List[str] = (
            malware_families
            if isinstance(malware_families, List)
            and all(
                isinstance(malware_family, str) for malware_family in malware_families
            )
            else []
        )

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """

        return {
            "objectid": self.objectid.as_primitives(),
            "name": self.name,
            "type": self.type,
            "attributes": [attribute.as_primitives() for attribute in self.attributes],
            "attacks": self.attacks,
            "actors": self.actors,
            "malware_families": self.malware_families,
        }


class Sandbox:
    class AnalysisMetadata:
        class MachineMetadata:
            def __init__(
                self,
                ip: Optional[str] = None,
                hypervisor: Optional[str] = None,
                hostname: Optional[str] = None,
                platform: Optional[str] = None,
                version: Optional[str] = None,
                architecture: Optional[str] = None,
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
                set_optional_argument(self, "ip", ip, str)
                set_optional_argument(self, "hypervisor", hypervisor, str)
                set_optional_argument(self, "hostname", hostname, str)
                set_optional_argument(self, "platform", platform, str)
                set_optional_argument(self, "version", version, str)
                set_optional_argument(self, "architecture", architecture, str)

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
            start_time: Optional[str] = None,
            task_id: Optional[int] = None,
            end_time: Optional[str] = None,
            routing: Optional[str] = None,
            machine_metadata: Optional[MachineMetadata] = None,
        ) -> None:
            """
            The metadata of the analysis, per analysis
            :param start_time: The start time of the analysis
            :param task_id: The ID used for identifying the analysis task
            :param end_time: The end time of the analysis
            :param routing: The routing used in the sandbox setup (Spoofed, Internet, Tor, VPN)
            :param machine_metadata: The metadata of the analysis
            """
            set_optional_argument(self, "start_time", start_time, str)
            if not self.start_time:
                self.start_time: str = MIN_TIME

            set_optional_argument(self, "task_id", task_id, int)

            set_optional_argument(self, "end_time", end_time, str)
            if not self.end_time:
                self.end_time: str = MAX_TIME

            set_optional_argument(self, "routing", routing, str)
            set_optional_argument(
                self, "machine_metadata", machine_metadata, self.MachineMetadata
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
            self.machine_metadata = self.MachineMetadata()
            self.machine_metadata.load_from_json(json["machine_metadata"])

    def __init__(
        self,
        objectid: ObjectID,
        analysis_metadata: AnalysisMetadata,
        sandbox_name: str,
        sandbox_version: Optional[str] = None,
    ) -> None:
        """
        The result ontology for sandbox output
        :param objectid: The object ID of the sandbox object
        :param analysis_metadata: Metadata for the analysis
        :param sandbox_name: The name of the sandbox
        :param sandbox_version: The version of the sandbox
        :return: None
        """
        set_required_argument(self, "objectid", objectid, ObjectID)
        set_required_argument(
            self, "analysis_metadata", analysis_metadata, self.AnalysisMetadata
        )
        set_required_argument(self, "sandbox_name", sandbox_name, str)
        set_optional_argument(self, "sandbox_version", sandbox_version, str)

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
        if not self.analysis_metadata.machine_metadata:
            self.analysis_metadata.machine_metadata = (
                self.AnalysisMetadata.MachineMetadata()
            )
        update_object_items(self.analysis_metadata.machine_metadata, kwargs)

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {
            "objectid": self.objectid.as_primitives(),
            "analysis_metadata": self.analysis_metadata.as_primitives(),
            "sandbox_name": self.sandbox_name,
            "sandbox_version": self.sandbox_version,
        }


class OntologyResults:
    def __init__(self, service_name: Optional[str] = None) -> None:
        """
        The OntologyResults class object which will contain and manipulate all data
        relating to the ontology results
        :param service_name: The name of the service this ontology result is being generated for
        :return: None
        """
        global SERVICE_NAME
        SERVICE_NAME = service_name

        self.netflows: List[NetworkConnection] = []
        self.dns_netflows: List[NetworkDNS] = []
        self.http_netflows: List[NetworkHTTP] = []
        self.processes: List[Process] = []
        self.sandboxes: List[Sandbox] = []
        self.signatures: List[Signature] = []
        self._guid_process_map: Dict[str, Process] = {}
        self.service_name = SERVICE_NAME

    # ObjectID manipulation methods
    @staticmethod
    def create_objectid(**kwargs) -> ObjectID:
        """
        This method creates an ObjectID, assigns its attributes based on keyword arguments provided,
        and returns the ObjectID
        :param kwargs: Key word arguments to be used for updating the ObjectID's attributes
        :return: ObjectID object
        """
        if not (kwargs.get("tag") and kwargs.get("ontology_id")):
            raise ValueError("The objectid needs its required arguments")
        objectid = ObjectID(
            kwargs["tag"], kwargs["ontology_id"], kwargs.get("service_name")
        )
        # Ensure that is time_observed is passed in and has a value, that that value is a str
        if "time_observed" in kwargs and kwargs["time_observed"] is not None and not isinstance(kwargs["time_observed"], str):
            raise ValueError("time_observed must be a str")
        # Ensure that time_observed is of a certain format
        elif "time_observed" in kwargs and kwargs["time_observed"] is not None and isinstance(kwargs["time_observed"], str):
            kwargs["time_observed"] = str(datetime.strptime(kwargs["time_observed"], LOCAL_FMT))
        update_object_items(objectid, kwargs)
        return objectid

    @staticmethod
    def create_session() -> str:
        """
        This method creates a random session ID, and a session ID == totally unique value separate from Sandbox Ontology ID
        :return: The session ID
        """
        return get_random_id()

    # Sandbox manipulation methods
    def set_sandboxes(self, sandboxes: List[Sandbox]) -> None:
        """
        This method sets the Sandbox objects
        :param sandboxes: The sandboxes to set
        :return: None
        """
        self.sandboxes = (
            sandboxes
            if isinstance(sandboxes, List)
            and all(isinstance(sandbox, Sandbox) for sandbox in sandboxes)
            else []
        )

    def add_sandbox(self, sandbox: Sandbox) -> None:
        """
        This method adds a Sandbox object to the list of sandboxes
        :param sandbox: The sandbox to add
        :return: None
        """
        self.sandboxes.append(sandbox)

    @staticmethod
    def create_sandbox(**kwargs) -> Sandbox:
        """
        This method creates a Sandbox object, assigns its attributes based on keyword arguments provided,
        and returns the Sandbox object
        :param kwargs: Key word arguments to be used for updating the Sandbox object's attributes
        :return: Sandbox object
        """
        if not (kwargs.get("objectid") and kwargs.get("sandbox_name")):
            raise ValueError("The sandbox needs its required arguments")
        sandbox = Sandbox(
            kwargs["objectid"], Sandbox.AnalysisMetadata(), kwargs["sandbox_name"]
        )

        update_object_items(sandbox, kwargs)
        if kwargs.get("analysis_metadata"):
            sandbox.update_analysis_metadata(
                **kwargs["analysis_metadata"].as_primitives()
            )
        return sandbox

    def get_sandbox_by_session(self, session: str) -> Optional[Sandbox]:
        """
        This method returns a Sandbox object that matches the given session
        :param session: The session that we are looking for sandboxes that match
        :return: A Sandbox object, if it exists
        """
        return next(
            (
                sandbox
                for sandbox in self.sandboxes
                if sandbox.objectid.session == session
            ),
            None,
        )

    def get_sandboxes(self) -> List[Sandbox]:
        """
        This method is a getter for the sandboxes attribute
        :return: The value of the sandboxes attribute
        """
        return self.sandboxes

    # Signature manipulation methods
    def set_signatures(self, signatures: List[Signature]) -> None:
        """
        This method sets the Signature objects
        :param signatures: The signatures to set
        :return: None
        """
        self.signatures = (
            signatures
            if isinstance(signatures, List)
            and all(isinstance(signature, Signature) for signature in signatures)
            else []
        )

    def create_signature(self, **kwargs) -> Signature:
        """
        This method creates a Signature object, assigns its attributes based on keyword arguments provided,
        and returns the Signature object
        :param kwargs: Key word arguments to be used for updating the Signature object's attributes
        :return: Signature object
        """
        if not (kwargs.get("objectid") and kwargs.get("name") and kwargs.get("type")):
            raise ValueError("The signature needs its required arguments")
        signature = Signature(kwargs["objectid"], kwargs["name"], kwargs["type"])
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
        signatures_with_pid: List[Signature] = []
        processes_with_pid = [
            process for process in self.processes if process.pid == pid
        ]
        for signature in self.signatures:
            for attribute in signature.attributes:
                if attribute.source.guid:
                    if any(
                        attribute.source.guid == process.objectid.guid
                        for process in processes_with_pid
                    ):
                        signatures_with_pid.append(signature)
                elif any(
                    attribute.source.ontology_id == process.objectid.ontology_id
                    for process in processes_with_pid
                ):
                    signatures_with_pid.append(signature)

        return signatures_with_pid

    @staticmethod
    def create_attribute(**kwargs) -> Attribute:
        """
        This method creates an Attribute, assigns its attributes based on keyword arguments provided,
        and returns the Attribute
        :param kwargs: Key word arguments to be used for updating the Attribute's attributes
        :return: Attribute object
        """
        return Signature.create_attribute(**kwargs)

    # NetworkConnection manipulation methods
    def set_netflows(self, network_connections: List[NetworkConnection]) -> None:
        """
        This method sets the NetworkConnection objects. Note that a netflow == NetworkConnection
        :param network_connections: The NetworkConnections to set
        :return: None
        """
        self.netflows: List[NetworkConnection] = (
            network_connections
            if isinstance(network_connections, List)
            and all(
                isinstance(network_connection, NetworkConnection)
                for network_connection in network_connections
            )
            else []
        )

    def create_network_connection(self, **kwargs) -> NetworkConnection:
        """
        This method creates a NetworkConnection object, assigns its attributes based on keyword arguments provided,
        and returns the NetworkConnection object
        :param kwargs: Key word arguments to be used for updating the NetworkConnection object's attributes
        :return: NetworkConnection object
        """
        if not (
            kwargs.get("objectid")
            and kwargs.get("destination_ip")
            and kwargs.get("destination_port")
            and kwargs.get("transport_layer_protocol")
            and kwargs.get("direction")
        ):
            raise ValueError("The network connection needs its required arguments")

        network_connection = NetworkConnection(
            kwargs["objectid"],
            kwargs["destination_ip"],
            kwargs["destination_port"],
            kwargs["transport_layer_protocol"],
            kwargs["direction"],
        )
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

        self.netflows.append(network_connection)

    def get_network_connections(self) -> List[NetworkConnection]:
        """
        This method returns the network connections
        :return: The list of network connections
        """
        return self.netflows

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

    def get_network_connection_by_details(
        self,
        destination_ip: str,
        destination_port: int,
        direction: str,
        transport_layer_protocol: str,
    ) -> NetworkConnection:
        """
        This method finds an existing network connection based on specific details
        NOTE: This isn't going to be the most exact method ever since it does not account for source IPs and ports
        :param destination_ip: The destination IP of the network connection
        :param destination_port: The destination port of the network connection
        :param direction: The direction of the network connection
        :param transport_layer_protocol: The transport layer protocol of the connection
        :return: The matching network connection, if it exists
        """
        # All or nothing!
        if any(
            item is None
            for item in [
                destination_ip,
                destination_port,
                direction,
                transport_layer_protocol,
            ]
        ):
            return None

        # Due to the way INetSim traffic can be handled, let's check for
        # network connections that are both HTTP and HTTPS
        if destination_port == 80:
            destination_ports = [80, 443]
        else:
            destination_ports = [destination_port]

        for network_connection in self.get_network_connections():
            if (
                network_connection.destination_ip == destination_ip
                and network_connection.destination_port in destination_ports
                and network_connection.direction == direction
                and network_connection.transport_layer_protocol
                == transport_layer_protocol
            ):
                return network_connection
        return None

    # NetworkDNS manipulation methods
    def set_dns_netflows(self, network_dns: List[NetworkDNS]) -> None:
        """
        This method sets the NetworkDNS objects. Note that a dns_netflow == NetworkDNS
        :param network_dnss: The NetworkDNS to set
        :return: None
        """
        self.dns_netflows: List[NetworkDNS] = (
            network_dns
            if isinstance(network_dns, List)
            and all(isinstance(dns, NetworkDNS) for dns in network_dns)
            else []
        )

    def create_network_dns(self, **kwargs) -> NetworkDNS:
        """
        This method creates a NetworkDNS object, assigns its attributes based on keyword arguments provided,
        and returns the NetworkDNS object
        :param kwargs: Key word arguments to be used for updating the NetworkDNS object's attributes
        :return: NetworkDNS object
        """
        if not (
            kwargs.get("domain")
            and kwargs.get("resolved_ips") is not None
            and kwargs.get("lookup_type")
        ):
            raise ValueError("The network dns connection needs its required arguments")
        network_dns = NetworkDNS(
            kwargs["domain"], kwargs["resolved_ips"], kwargs["lookup_type"]
        )
        update_object_items(network_dns, kwargs)
        return network_dns

    def add_network_dns(self, dns: NetworkDNS) -> None:
        """
        This method adds a NetworkDNS object to the list of network DNS calls
        :param dns: The NetworkDNS object to be added
        :return: None
        """
        self.dns_netflows.append(dns)

    def get_network_dns(self) -> List[NetworkDNS]:
        """
        This method returns the network dns
        :return: The list of network dns
        """
        return self.dns_netflows

    def get_domain_by_destination_ip(self, ip: str) -> Optional[str]:
        """
        This method returns domains associated with a given destination IP
        :param ip: The IP for which an associated domain is requested
        :return: The domain associated with the given destination IP
        """
        domains = [dns.domain for dns in self.dns_netflows if ip in dns.resolved_ips]
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
        ips = [dns.resolved_ips[0] for dns in self.dns_netflows if domain == dns.domain]
        if ips:
            return ips[0]
        else:
            return None

    # NetworkHTTP manipulation methods
    def set_http_netflows(self, network_http: List[NetworkHTTP]) -> None:
        """
        This method sets the NetworkHTTP objects. Note that a http_netflow == NetworkHTTP
        :param network_http: The NetworkHTTPs to set
        :return: None
        """
        self.http_netflows: List[NetworkHTTP] = (
            network_http
            if isinstance(network_http, List)
            and all(isinstance(http, NetworkHTTP) for http in network_http)
            else []
        )

    def create_network_http(self, **kwargs) -> NetworkHTTP:
        """
        This method creates a NetworkHTTP object, assigns its attributes based on keyword arguments provided,
        and returns the NetworkHTTP object
        :param kwargs: Key word arguments to be used for updating the NetworkHTTP object's attributes
        :return: NetworkHTTP object
        """
        if not (kwargs.get("request_uri") and kwargs.get("request_method")):
            raise ValueError("The network http connection needs its required arguments")
        network_http = NetworkHTTP(kwargs["request_uri"], kwargs["request_method"])
        update_object_items(network_http, kwargs)
        return network_http

    def add_network_http(self, http: NetworkHTTP) -> None:
        """
        This method adds a NetworkHTTP object to the list of network HTTP calls
        :param http: The NetworkHTTP object to be added
        :return: None
        """
        self.http_netflows.append(http)

    def get_network_http(self) -> List[NetworkHTTP]:
        """
        This method returns the network HTTP
        :return: The list of network HTTP
        """
        return self.http_netflows

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
        self, request_uri: str, request_method: str, request_headers: Dict[str, str]
    ) -> Optional[NetworkHTTP]:
        """
        This request_method gets a network http call by request URI, request_method and request headers
        :param request_uri: The URI of the request
        :param request_method: The request_method used for the HTTP request
        :param request_headers: The headers of the request
        :return: The network http call (should one exist) that matches these details
        """
        network_http_with_details = [
            http
            for http in self.get_network_http()
            if http.request_uri == request_uri
            and http.request_method == request_method
            and http.request_headers == request_headers
        ]
        if not network_http_with_details:
            return None
        else:
            return network_http_with_details[0]

    def get_network_connection_by_network_http(self, network_http: NetworkHTTP) -> Optional[NetworkHTTP]:
        """
        This method returns the network connection corresponding to the given network http object
        :param network_http: The given network http object
        :return: The corresponding network connection
        """
        return next((netflow for netflow in self.netflows if netflow.http_details == network_http), None)

    # Process manipulation methods
    def set_processes(self, processes: List[Process]) -> None:
        """
        This method sets the Process objects.
        :param processes: The Processes to set
        :return: None
        """
        self.processes: List[Process] = (
            processes
            if isinstance(processes, List)
            and all(isinstance(process, Process) for process in processes)
            else []
        )

    def create_process(self, **kwargs) -> Process:
        """
        This method creates a Process object, assigns its attributes based on keyword arguments provided,
        and returns the Process object
        :param kwargs: Key word arguments to be used for updating the Process object's attributes
        :return: Process object
        """
        if not (
            kwargs.get("objectid") and kwargs.get("image") and kwargs.get("start_time")
        ):
            raise ValueError("The process needs its required arguments")
        process = Process(kwargs["objectid"], kwargs["image"], kwargs["start_time"])
        process.update(**kwargs)

        if not process.objectid.guid:
            process.objectid.assign_guid()
        if not process.end_time:
            process.set_end_time(MAX_TIME)
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
            log.debug("Invalid process, ignoring...")
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
        parent_keys = [
            "pguid",
            "ptag",
            "ptreeid",
            "pprocesstree",
            "ptime_observed",
            "ppid",
            "pimage",
            "pcommand_line",
            "pobjectid",
        ]
        parent_kwargs = {
            key[1:]: value for key, value in kwargs.items() if key in parent_keys
        }

        if "guid" in kwargs and kwargs["guid"]:
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
            if not isinstance(timestamp, str):
                raise ValueError(f"The timestamp {timestamp} must be a str")

            guid = self.get_guid_by_pid_and_time(kwargs["pid"], timestamp)
            if not guid:
                p = self.create_process(**kwargs)
                self.add_process(p)
                return
            process_to_update = self.get_process_by_guid(guid)
            kwargs["guid"] = guid
            if process_to_update:
                process_to_update.update(**kwargs)

        if parent_kwargs.get("guid") or parent_kwargs.get("pobjectid", {}).get("guid"):
            # Only update if ObjectID is not associated with another process
            if process_to_update and any(
                process_to_update.pobjectid == process.objectid
                for process in self.get_processes()
            ):
                return
            pguid = (
                parent_kwargs["guid"]
                if parent_kwargs.get("guid")
                else parent_kwargs.get("pobjectid", {}).get("guid")
            )
            parent = self.get_process_by_guid(pguid)
            if process_to_update and parent:
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
        if process.pobjectid and process.pobjectid.guid:
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

    def get_guid_by_pid_and_time(self, pid: int, timestamp: str) -> Optional[str]:
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
        self, ppid: int, timestamp: str
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

    def get_pguid_by_pid_and_time(self, pid: int, timestamp: str) -> Optional[str]:
        """
        This method allows the retrieval of the parent process's GUID based on a process ID and timestamp
        :param pid: The process ID
        :param timestamp: A timestamp between the creation and termination of a process
        :return: The parent process's GUID for the given process ID
        """
        process = self.get_process_by_pid_and_time(pid, timestamp)
        if process and process.pobjectid:
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

    def get_process_by_command_line(
        self, command_line: Optional[str] = None
    ) -> Optional[Process]:
        """
        This method takes a given command line and returns the associated process
        NOTE That this method has a high possibility of not being accurate. If multiple processes use the same
        command line, this method will return the first process.
        :param command_line: The given command line that we want an associated process for
        :return: The associated process
        """
        if not command_line:
            return None

        processes_with_command_line = [
            process
            for process in self.get_processes()
            if process.command_line
            and (
                command_line == process.command_line
                or command_line in process.command_line
            )
        ]
        if not processes_with_command_line:
            return None
        else:
            return processes_with_command_line[0]

    def get_process_by_pid_and_time(
        self, pid: Optional[int], timestamp: Optional[str]
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
            if process.pobjectid and process.pobjectid.guid == pguid
        ]

    def get_process_by_pid(self, pid: Optional[int] = None) -> Optional[Process]:
        """
        This method takes a given process ID and returns the associated process
        NOTE That this method has a high possibility of not being accurate. If multiple processes use the same
        process ID, this method will return the first process.
        :param pid: The given process ID that we want an associated process for
        :return: The associated process
        """
        if not pid:
            return None

        processes_with_pid = [
            process
            for process in self.get_processes()
            if process.pid and pid == process.pid
        ]
        if not processes_with_pid:
            return None
        else:
            return processes_with_pid[0]

    def as_primitives(self) -> Dict[str, Any]:
        """
        This method returns the dictionary representation of the object
        :return: The dictionary representation of the object
        """
        return {
            "sandboxes": [sandbox.as_primitives() for sandbox in self.sandboxes],
            "signatures": [signature.as_primitives() for signature in self.signatures],
            "network_connections": [
                network_connection.as_primitives()
                for network_connection in self.netflows
            ],
            "network_dns": [
                network_dns.as_primitives() for network_dns in self.dns_netflows
            ],
            "network_http": [
                network_http.as_primitives() for network_http in self.http_netflows
            ],
            "processes": [process.as_primitives() for process in self.processes],
        }

    # Process Tree and Event manipulation methods
    def get_events(
        self, safelist: List[str] = None
    ) -> List[Union[Process, NetworkConnection]]:
        """
        This method gets all process and network events, sorts them by time observed, and returns a list
        :param safelist: A list of safe treeids
        :return: A sorted list of all process and network events
        """
        if safelist is None:
            safelist: List[str] = []

        processes_to_add = [
            process
            for process in self.processes
            if process.start_time is not None
            and process.objectid.treeid not in safelist
        ]
        netflows_to_add = [
            network_connection
            for network_connection in self.netflows
            if network_connection.objectid.time_observed is not None
            and network_connection.objectid.treeid not in safelist
        ]
        events = processes_to_add + netflows_to_add
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
            tree = OntologyResults._filter_event_tree_against_safe_treeids(
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
            self._convert_event_tree_to_result_section(
                items, event, safelist, process_tree_result_section
            )
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
        injection_heur_id: int = 17,
    ) -> ResultSection:
        """
        Goes through each artifact in artifact_list, uploading them and adding result sections accordingly
        :param artifact_list: List of dictionaries that each represent an artifact
        :param collapsed: A flag used for indicating if the Sandbox Artifacts ResultSection should be collapsed or not
        :param injection_heur_id: The heuristic ID for the Injection heuristic of a service
        :return: A ResultSection containing any Artifact ResultSections
        """

        validated_artifacts = OntologyResults._validate_artifacts(artifact_list)

        artifacts_result_section = ResultSection(
            "Sandbox Artifacts", auto_collapse=collapsed
        )

        for artifact in validated_artifacts:
            OntologyResults._handle_artifact(
                artifact, artifacts_result_section, injection_heur_id
            )

            if artifact.to_be_extracted and not any(artifact.sha256 == previously_extracted["sha256"] for previously_extracted in request.extracted):
                try:
                    request.add_extracted(
                        artifact.path, artifact.name, artifact.description
                    )
                except MaxExtractedExceeded:
                    # To avoid errors from being raised when too many files have been extracted
                    pass
            elif not artifact.to_be_extracted and not any(artifact.sha256 == previously_supplemented["sha256"] for previously_supplemented in request.task.supplementary):
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
        # elif not process.objectid.guid and process.pid not in pids:
        #     # This means we have a unique process that is not yet in the lookup table.
        #     # Before we add it, assign a GUID to it.
        #     process.objectid.assign_guid()
        elif process.objectid.guid in guids and process.pid in pids:
            # We cannot have two items in the table that share process IDs and GUIDs
            log.debug("Duplicate process, skipping...")
            return False
        elif process.objectid.guid in guids and process.pid not in pids:
            # We cannot have two items in the table that share GUIDs
            log.debug("Duplicate process, skipping...")
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
            self.http_netflows.remove(network_http)
        except ValueError:
            return

    def _remove_network_dns(self, network_dns: NetworkDNS) -> None:
        """
        This method takes a network_dns and removes it from the current network_dns calls, if it exists
        :param network_dns: The network_dns to be removed
        :return: None
        """
        try:
            self.dns_netflows.remove(network_dns)
        except ValueError:
            return

    def _remove_network_connection(self, network_connection: NetworkConnection) -> None:
        """
        This method takes a network_connection and removes it from the current network_connections, if it exists
        :param network_connection: The network_connection to be removed
        :return: None
        """
        try:
            self.netflows.remove(network_connection)
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
                # We should only be sorting with floats
                time_obs = x["objectid"]["time_observed"]
                if isinstance(time_obs, str):
                    if time_obs == MIN_TIME:
                        time_obs = epoch_to_local(0)
                    time_obs = datetime.strptime(
                        time_obs, LOCAL_FMT
                    ).timestamp()
                return time_obs

        else:

            if any(
                thing_to_sort_by_time_observed.objectid.time_observed is None
                for thing_to_sort_by_time_observed in things_to_sort_by_time_observed
            ):
                log.warning("All ObjectID time_observed values must not be None...")
                return things_to_sort_by_time_observed

            def time_observed(x):
                # We should only be sorting with floats
                time_obs = x.objectid.time_observed
                if isinstance(time_obs, str):
                    if time_obs == MIN_TIME:
                        time_obs = epoch_to_local(0)
                    time_obs = datetime.strptime(
                        time_obs, LOCAL_FMT
                    ).timestamp()
                return time_obs

        sorted_things = sorted(things_to_sort_by_time_observed, key=time_observed)
        return sorted_things

    @staticmethod
    def _sort_things_by_relationship(
        things_to_sort_by_relationship: List[Union[Process, NetworkConnection, Dict]]
    ) -> List[Union[Process, NetworkConnection, Dict]]:
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
                for parent_index, parent in enumerate(
                    things_to_sort_by_relationship[index + 1 :]
                ):
                    if (
                        pobjectid["guid"] == parent["objectid"]["guid"]
                        and pobjectid["time_observed"]
                        == parent["objectid"]["time_observed"]
                    ):
                        popped_item = things_to_sort_by_relationship.pop(
                            index + 1 + parent_index
                        )
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
                for parent_index, parent in enumerate(
                    things_to_sort_by_relationship[index + 1 :]
                ):
                    if thing.pobjectid.guid == parent.objectid.guid:
                        popped_item = things_to_sort_by_relationship.pop(
                            index + 1 + parent_index
                        )
                        things_to_sort_by_relationship.insert(index, popped_item)
                        recurse_again = True
                        break
                if recurse_again:
                    break

        if recurse_again:
            OntologyResults._sort_things_by_relationship(things_to_sort_by_relationship)
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
    def _depth(d: Dict[str, Any]) -> int:
        """
        This method uses recursion to determine the depth of a dictionary
        :param d: The dictionary to determine the depth of
        :return: The integer value representing the current depth at the current iteration
        """
        if isinstance(d, dict):
            children = d.get("children", [])
            if isinstance(children, list):
                if not children:
                    return 1
                return 1 + max(OntologyResults._depth(child) for child in children)
        return 0

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
        sorted_events = OntologyResults._sort_things_by_time_observed(
            list(events_dict.values())
        )
        try:
            # If events all have the same time observed, but there are child-parent relationships between events,
            # we should order based on relationship
            sorted_events_by_relationship_and_time = (
                OntologyResults._sort_things_by_relationship(sorted_events)
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
            if "pobjectid" in e and e["pobjectid"] and e["pobjectid"]["guid"]:
                # This is a Process
                pguid = e["pobjectid"]["guid"]
            elif "process" in e and e["process"] and e["process"]["objectid"]["guid"]:
                # This is a NetworkConnection
                pguid = e["process"]["objectid"]["guid"]

            if pguid and pguid in events_seen:
                # Check if depth is too DEEP
                if any(OntologyResults._depth(event_dict) >= PROCESS_TREE_DEPTH_LIMIT for event_dict in events_dict.values()):
                    # We still want to register the process in events_seen, so
                    # that they don't get added to the root children
                    pass
                else:
                    events_dict[pguid]["children"].append(e)
            else:
                root["children"].append(e)

            events_seen.append(e["objectid"]["guid"])

        return OntologyResults._sort_things_by_time_observed(root["children"])

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
            result_section.add_tag(
                "dynamic.processtree_id", event["objectid"]["processtree"]
            )
            if event["command_line"]:
                result_section.add_tag(
                    "dynamic.process.command_line", event["command_line"]
                )

        for signature in self.get_signatures_by_pid(event["pid"]):
            if signature.score is None:
                signature.set_score(0)
            e.add_signature(signature.name, signature.score)

        for child in event["children"][:]:
            # A telltale sign that the event is a NetworkConnection
            if "process" in child:
                # event is a NetworkConnection, we don't want this in the process tree result section, only the counts
                pass
            else:
                self._convert_event_tree_to_result_section(
                    items, child, safelist, result_section, parent=e
                )
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
        elif node.get("pobjectid") and node["pobjectid"].get("processtree"):
            processtree = f"{node['pobjectid']['processtree']}|{tag}"
        elif node.get("pobjectid") and node["pobjectid"].get("tag"):
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
            hash_to_remove = OntologyResults._remove_safe_leaves_helper(
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
            _ = OntologyResults._remove_safe_leaves_helper(root, safe_treeids)
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
        OntologyResults._remove_safe_leaves(event_tree, safe_treeids)
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
                sha256=artifact["sha256"] if artifact.get("sha256") else get_sha256_for_file(artifact["path"])
            )
            validated_artifacts.append(validated_artifact)
        return validated_artifacts

    @staticmethod
    def _handle_artifact(
        artifact: Artifact = None,
        artifacts_result_section: ResultSection = None,
        injection_heur_id: int = 17,
    ) -> None:
        """
        This method handles a single artifact and creates a ResultSection for the artifact, if appropriate
        :param artifact: An artifact object
        :param artifacts_result_section: A master ResultSection that will contain the ResultSection created for the
        given artifact
        :param injection_heur_id: The heuristic ID for the Injection heuristic of a service
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
                    artifact_result_section.set_heuristic(injection_heur_id)
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
            start_time = next(
                (
                    sandbox.analysis_metadata.start_time
                    for sandbox in self.sandboxes
                    if sandbox.objectid.session == item.objectid.session
                ),
                None,
            )
            end_time = next(
                (
                    sandbox.analysis_metadata.end_time
                    for sandbox in self.sandboxes
                    if sandbox.objectid.session == item.objectid.session
                ),
                None,
            )
            if start_time == MIN_TIME:
                start_time = epoch_to_local(0)
            if item.start_time == MIN_TIME:
                item.set_start_time(start_time)
            if item.end_time == MAX_TIME:
                item.set_end_time(end_time)
            if item.objectid.time_observed == MIN_TIME:
                item.objectid.set_time_observed(start_time)
            if item.objectid.time_observed == MAX_TIME:
                item.objectid.set_time_observed(end_time)
            if item.pobjectid and item.pobjectid.time_observed == MIN_TIME:
                item.pobjectid.set_time_observed(start_time)
            if item.pobjectid and item.pobjectid.time_observed == MAX_TIME:
                item.pobjectid.set_time_observed(end_time)
        elif isinstance(item, ObjectID):
            start_time = next(
                (
                    sandbox.analysis_metadata.start_time
                    for sandbox in self.sandboxes
                    if sandbox.objectid.session == item.session
                ),
                None,
            )
            end_time = next(
                (
                    sandbox.analysis_metadata.end_time
                    for sandbox in self.sandboxes
                    if sandbox.objectid.session == item.session
                ),
                None,
            )
            if start_time == MIN_TIME:
                start_time = epoch_to_local(0)
            if item.time_observed == MIN_TIME:
                item.set_time_observed(start_time)
            elif item.time_observed == MAX_TIME:
                item.set_time_observed(end_time)
        else:
            log.warning(f"Given object {item} is neither Process or ObjectID...")

    def _remove_safelisted_processes(
        self, safelist: List[str], need_tree_id: bool = False
    ) -> None:
        """
        This method removes all safelisted processes and all activities associated with those processes
        :param need_tree_id:
        :return: None
        """
        safelisted_processes = [
            process
            for process in self.get_processes()
            if process.objectid.treeid in safelist
            or (need_tree_id and process.objectid.treeid is None)
        ]

        safelisted_network_connections = [
            nc
            for nc in self.get_network_connections()
            if nc.process in safelisted_processes
        ]
        safelisted_network_http = [
            nc.http_details for nc in safelisted_network_connections if nc.http_details
        ]
        safelisted_network_dns = [
            nc.dns_details for nc in safelisted_network_connections if nc.dns_details
        ]
        safelisted_signatures = [
            sig
            for sig in self.get_signatures()
            if any(
                all(
                    attribute.source == safelisted_process.objectid
                    for attribute in sig.attributes
                )
                for safelisted_process in safelisted_processes
            )
        ]
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

    def preprocess_ontology(
        self, safelist: List[str] = None, from_main: bool = False, so_json: str = None
    ) -> None:
        """
        This method preprocesses the ontology before it gets validated by Assemblyline's base ODM
        :param from_main: A boolean flag that indicates if this method is being run from __main__
        :param so_json: The path to the json file that represents the Sandbox Ontology
        :return: None
        """
        if safelist is None:
            safelist: List[str] = []

        self._remove_safelisted_processes(safelist, need_tree_id=True)

        for process in self.get_processes():
            self._set_item_times(process)

        for signature in self.get_signatures():
            for subject in signature.get_attributes():
                self._set_item_times(subject.source)

        for network_connection in self.get_network_connections():
            self._set_item_times(network_connection.process)


def attach_dynamic_ontology(service: ServiceBase, ontres: OntologyResults) -> None:
    """
    This method takes a given service instance and an instance of the OntologyResults class and adds the ontologies
    :param service: The service instance that will have ontologies added to it
    :param ontres: The OntologyResults instance that contains the ontologies data
    :return: None
    """
    [service.ontology.add_result_part(ProcessModel, process.as_primitives()) for process in ontres.get_processes()]
    [service.ontology.add_result_part(SandboxModel, sandbox.as_primitives()) for sandbox in ontres.get_sandboxes()]
    [service.ontology.add_result_part(SignatureModel, signature.as_primitives()) for signature in ontres.get_signatures()]
    [service.ontology.add_result_part(NetworkConnectionModel, network_connection.as_primitives()) for network_connection in ontres.get_network_connections()]


def extract_iocs_from_text_blob(
    blob: str,
    result_section: ResultTableSection,
    so_sig: Optional[Signature] = None,
    source: Optional[ObjectID] = None,
    enforce_char_min: bool = False,
    enforce_domain_char_max: bool = False,
    safelist: Dict[str, Dict[str, List[str]]] = None,
    is_network_static: bool = False
) -> None:
    """
    This method searches for domains, IPs and URIs used in blobs of text and tags them
    :param blob: The blob of text that we will be searching through
    :param result_section: The result section that that tags will be added to
    :param so_sig: The signature for the Ontology Results
    :param source: The source of the signature for the Ontology Results
    :param enforce_char_min: Enforce the minimum amount of characters that an ioc can have
    :param enforce_domain_char_max: Enforce the maximum amount of characters that a domain can have
    :param safelist: The safelist containing matches and regexs. The product of a
                     service using self.get_api_interface().get_safelist().
    :param is_network_static: Should we tag these IOCs as static or dynamic? Default to dynamic since this method
                        is in the dynamic service helper module.
    :return: None
    """
    if not blob:
        return

    if is_network_static:
        network_tag_type = "static"
    else:
        network_tag_type = "dynamic"

    blob = blob.lower()
    ips = set(findall(IP_REGEX, blob))
    # There is overlap here between regular expressions, so we want to isolate domains that are not ips
    domains = set(findall(DOMAIN_REGEX, blob)) - ips
    # There is overlap here between regular expressions, so we want to isolate uris that are not domains
    # TODO: Are we missing IOCs to the point where we need a different regex?
    # uris = {uri.decode() for uri in set(findall(PatternMatch.PAT_URI_NO_PROTOCOL, blob.encode()))} - domains - ips
    uris = set(findall(URL_REGEX, blob)) - domains - ips
    for ip in ips:
        if add_tag(result_section, f"network.{network_tag_type}.ip", ip, safelist):
            if not result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="ip", ioc=ip))
            elif (
                dumps({"ioc_type": "ip", "ioc": ip})
                not in result_section.section_body.body
            ):
                result_section.add_row(TableRow(ioc_type="ip", ioc=ip))
    for domain in domains:
        if enforce_char_min and len(domain) < MIN_DOMAIN_CHARS:
            continue
        if enforce_domain_char_max and len(domain) > MAX_DOMAIN_CHARS:
            continue
        # File names match the domain and URI regexes, so we need to avoid tagging them
        # Note that get_tld only takes URLs so we will prepend http:// to the domain to work around this
        if add_tag(result_section, f"network.{network_tag_type}.domain", domain, safelist):
            if not result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="domain", ioc=domain))
            elif (
                dumps({"ioc_type": "domain", "ioc": domain})
                not in result_section.section_body.body
            ):
                result_section.add_row(TableRow(ioc_type="domain", ioc=domain))

    for uri in uris:
        if enforce_char_min and len(uri) < MIN_URI_CHARS:
            continue
        if any(invalid_uri_char in uri for invalid_uri_char in ['"', "'", '<', '>', "(", ")"]):
            for invalid_uri_char in ['"', "'", '<', '>', "(", ")"]:
                for u in uri.split(invalid_uri_char):
                    if re_match(FULL_URI, u):
                        uri = u
                        break
        if add_tag(result_section, f"network.{network_tag_type}.uri", uri, safelist):
            if not result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="uri", ioc=uri))
            elif (
                dumps({"ioc_type": "uri", "ioc": uri})
                not in result_section.section_body.body
            ):
                result_section.add_row(TableRow(ioc_type="uri", ioc=uri))
            if so_sig and source:
                so_sig.add_attribute(so_sig.create_attribute(source=source, uri=uri))
        if "//" in uri:
            uri = uri.split("//")[1]
        for uri_path in findall(URI_PATH, uri):
            if enforce_char_min and len(uri_path) < MIN_URI_PATH_CHARS:
                continue
            if add_tag(result_section, f"network.{network_tag_type}.uri_path", uri_path, safelist):
                if not result_section.section_body.body:
                    result_section.add_row(TableRow(ioc_type="uri_path", ioc=uri_path))
                elif (
                    dumps({"ioc_type": "uri_path", "ioc": uri_path})
                    not in result_section.section_body.body
                ):
                    result_section.add_row(TableRow(ioc_type="uri_path", ioc=uri_path))


# DEBUGGING METHOD
if __name__ == "__main__":
    # This method is for validating the output from the OntologyResults class -> Sandbox class
    from sys import argv

    so_json_path = argv[1]
    default_so = OntologyResults()
    default_so.preprocess_ontology(safelist=[], from_main=True, so_json=so_json_path)
