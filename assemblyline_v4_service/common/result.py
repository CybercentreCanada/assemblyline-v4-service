from __future__ import annotations

import json
import logging
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Optional, TextIO, Union

from assemblyline.common import log as al_log
from assemblyline.common.attack_map import attack_map, group_map, revoke_map, software_map
from assemblyline.common.classification import Classification
from assemblyline.common.dict_utils import unflatten
from assemblyline.common.str_utils import StringTable, safe_str
from assemblyline_v4_service.common.helper import get_heuristics, get_service_attributes

if TYPE_CHECKING:  # Avoid circular dependency
    from assemblyline_v4_service.common.request import ServiceRequest

# Type of values in KV sections
KV_VALUE_TYPE = Union[str, bool, int]

al_log.init_logging('service.result')
log = logging.getLogger('assemblyline.service.result')

SERVICE_ATTRIBUTES = None
HEUR_LIST = None

# This is a StringTable representation of the BODY_FORMAT set of keys in
# assemblyline-base/assemblyline/odm/models/result.py.
# Any updates here need to go in that set of keys also.
BODY_FORMAT = StringTable('BODY_FORMAT', [
    ('TEXT', 0),
    ('MEMORY_DUMP', 1),
    ('GRAPH_DATA', 2),
    ('URL', 3),
    ('JSON', 4),
    ('KEY_VALUE', 5),
    ('PROCESS_TREE', 6),
    ('TABLE', 7),
    ('IMAGE', 8),
    ('MULTI', 9),
    ('DIVIDER', 10),  # This is not a real result section and can only be use inside a multi section
    ('ORDERED_KEY_VALUE', 11),
    ('TIMELINE', 12),
    ('SANDBOX', 13),
])

# This is a StringTable representation of the PROMOTE_TO set of keys in
# assemblyline-base/assemblyline/odm/models/result.py.
# Any updates here need to go in that set of keys also.
PROMOTE_TO = StringTable('PROMOTE_TO', [
    ('SCREENSHOT', 0),
    ('ENTROPY', 1),
    ('URI_PARAMS', 2)
])


class InvalidHeuristicException(Exception):
    pass


class InvalidFunctionException(Exception):
    pass


class ResultAggregationException(Exception):
    pass


def get_heuristic_primitives(heur: Optional[Heuristic]) -> Optional[Dict[str, Union[int, List[str], Dict[str, int]]]]:
    if heur is None:
        return None

    return dict(
        heur_id=heur.heur_id,
        score=heur.score,
        attack_ids=heur.attack_ids,
        signatures=heur.signatures,
        frequency=heur.frequency,
        score_map=heur.score_map
    )


class Heuristic:
    def __init__(self, heur_id: int,
                 attack_id: Optional[str] = None,
                 signature: Optional[str] = None,
                 attack_ids: Optional[List[str]] = None,
                 signatures: Optional[Dict[str, int]] = None,
                 frequency: int = 1,
                 score_map: Optional[Dict[str, int]] = None):

        # Lazy load heuristics
        global HEUR_LIST
        if not HEUR_LIST:
            HEUR_LIST = get_heuristics()

        # Validate heuristic
        if heur_id not in HEUR_LIST:
            raise InvalidHeuristicException(f"Invalid heuristic. A heuristic with ID: {heur_id}, must be added to "
                                            f"the service manifest before using it.")

        # Set default values
        self._definition = HEUR_LIST[heur_id]
        self._heur_id = heur_id
        self._attack_ids = []
        self._frequency = 0

        # Live score map is either score_map or an empty map
        self._score_map = score_map or {}

        # Default attack_id list is either empty or received attack_ids parameter
        attack_ids = attack_ids or []

        # If an attack_id is specified, append it to attack id list
        if attack_id:
            attack_ids.append(attack_id)

        # If no attack_id are set, check heuristic definition for a default attack id
        if not attack_ids and self._definition.attack_id:
            attack_ids.extend(self._definition.attack_id)

        # Validate that all attack_ids are in the attack_map
        for a_id in attack_ids:
            if a_id in attack_map or a_id in software_map or a_id in group_map:
                self._attack_ids.append(a_id)
            elif a_id in revoke_map:
                self._attack_ids.append(revoke_map[a_id])
            else:
                log.warning(f"Invalid attack_id '{a_id}' for heuristic '{heur_id}'. Ignoring it.")

        # Signature map is either the provided value or an empty map
        self._signatures = signatures or {}

        # If a signature is provided, add it to the map and increment its frequency
        if signature:
            self._signatures.setdefault(signature, 0)
            self._signatures[signature] += frequency

        # If there are no signatures, add an empty signature with frequency of one (signatures drives the score)
        if not self._signatures:
            self._frequency = frequency

    @property
    def attack_ids(self):
        return self._attack_ids

    @property
    def description(self):
        return self._definition.description

    @property
    def frequency(self):
        return self._frequency

    @property
    def heur_id(self):
        return self._heur_id

    @property
    def name(self):
        return self._definition.name

    @property
    def score(self):
        temp_score = 0
        if len(self._signatures) > 0:
            # There are signatures associated to the heuristic, loop through them and compute a score
            for sig_name, freq in self._signatures.items():
                # Find which score we should use for this signature (In order of importance)
                #   1. Heuristic's signature score map
                #   2. Live service submitted score map
                #   3. Heuristic's default signature
                sig_score = self._definition.signature_score_map.get(sig_name,
                                                                     self._score_map.get(sig_name,
                                                                                         self._definition.score))
                temp_score += sig_score * freq
        else:
            # There are no signatures associated to the heuristic, compute the new score based of that new frequency
            frequency = self._frequency or 1
            temp_score = self._definition.score * frequency

        # Checking score boundaries
        if self._definition.max_score:
            temp_score = min(temp_score, self._definition.max_score)

        return temp_score

    @property
    def score_map(self):
        return self._score_map

    @property
    def signatures(self):
        return self._signatures

    def add_attack_id(self, attack_id: str):
        if attack_id not in self._attack_ids:
            if attack_id in attack_map or attack_id in software_map or attack_id in group_map:
                self._attack_ids.append(attack_id)
            elif attack_id in revoke_map:
                new_attack_id = revoke_map[attack_id]
                if new_attack_id not in self._attack_ids:
                    self._attack_ids.append(new_attack_id)
            else:
                log.warning(f"Invalid attack_id '{attack_id}' for heuristic '{self._heur_id}'. Ignoring it.")

    def add_signature_id(self, signature: str, score: int = None, frequency: int = 1):
        # Add the signature to the map and adds it new frequency to the old value
        self._signatures.setdefault(signature, 0)
        self._signatures[signature] += frequency

        # If a new score is assigned to the signature save it here
        if score is not None:
            self._score_map[signature] = score

    def increment_frequency(self, frequency: int = 1):
        # Increment the signature less frequency of the heuristic
        self._frequency += frequency


class SectionBody:
    def __init__(self, body_format, body=None):
        self._format = body_format
        self._data = body
        self._config = {}

    @property
    def format(self):
        return self._format

    @property
    def body(self) -> str | None:
        if not self._data:
            return None
        elif not isinstance(self._data, str):
            return json.dumps(self._data, allow_nan=False)
        else:
            return self._data

    @property
    def config(self) -> dict:
        return self._config

    def set_body(self, body):
        self._data = body


class TextSectionBody(SectionBody):
    def __init__(self, body=None) -> None:
        super().__init__(BODY_FORMAT.TEXT, body=body)

    def add_line(self, text: Union[str, List]) -> Optional[str]:
        # add_line with a list should join without newline seperator.
        # use add_lines if list should be split one element per line.
        if text is None:
            raise ValueError("Expected text to add to a line must be a string or a list, not None.")

        if isinstance(text, list):
            text = ''.join(text)
        textstr = safe_str(text)
        if self._data:
            self._data = f"{self._data}\n{textstr}"
        else:
            self._data = textstr
        return self._data

    def add_lines(self, line_list: List[str]) -> Optional[str]:
        if not line_list:
            return self._data

        if not isinstance(line_list, list):
            return self._data

        segment = safe_str('\n'.join(line_list))
        if self._data is None:
            self._data = segment
        else:
            self._data = f"{self._data}\n{segment}"
        return self._data


class MemorydumpSectionBody(SectionBody):
    def __init__(self, body=None) -> None:
        super().__init__(BODY_FORMAT.MEMORY_DUMP, body=body)


class URLSectionBody(SectionBody):
    def __init__(self) -> None:
        super().__init__(BODY_FORMAT.URL, body=[])

    def add_url(self, url: str, name: Optional[str] = None) -> None:
        if not url:
            raise ValueError("A valid URL is required. An empty URL was passed.")

        url_data = {'url': url}
        if name:
            url_data['name'] = name
        self._data.append(url_data)


class GraphSectionBody(SectionBody):
    def __init__(self) -> None:
        super().__init__(BODY_FORMAT.GRAPH_DATA)

    def set_colormap(self, cmap_min: int, cmap_max: int, values: List[int]) -> None:
        cmap = {'type': 'colormap',
                'data': {
                    'domain': [cmap_min, cmap_max],
                    'values': values
                }}
        self._data = cmap


class KVSectionBody(SectionBody):
    def __init__(self, **kwargs: KV_VALUE_TYPE) -> None:
        self._data: dict[str, KV_VALUE_TYPE]
        super().__init__(BODY_FORMAT.KEY_VALUE, body=kwargs)

    def set_item(self, key: str, value: KV_VALUE_TYPE) -> None:
        self._data[str(key)] = value

    def update_items(self, new_dict: dict[str, KV_VALUE_TYPE]) -> None:
        self._data.update({str(k): v for k, v in new_dict.items()})


class OrderedKVSectionBody(SectionBody):
    def __init__(self, **kwargs: KV_VALUE_TYPE) -> None:
        self._data: list[tuple[str, KV_VALUE_TYPE]]
        super().__init__(BODY_FORMAT.ORDERED_KEY_VALUE, body=[(str(key), value) for key, value in kwargs.items()])

    def add_item(self, key: str, value: KV_VALUE_TYPE) -> None:
        self._data.append((str(key), value))


class JSONSectionBody(SectionBody):
    def __init__(self) -> None:
        super().__init__(BODY_FORMAT.JSON, body={})

    def set_json(self, json_body: dict) -> None:
        self._data = json_body

    def update_json(self, json_body: dict) -> None:
        self._data.update(json_body)


class ProcessItem:
    def __init__(
            self, pid: int, name: str, cmd: str, signatures: Optional[Dict[str, int]] = None,
            children: Optional[List[ProcessItem]] = None, network_count: int = 0, file_count: int = 0,
            registry_count: int = 0, safelisted: bool = False):

        self.pid = pid
        self.name = name
        self.cmd = cmd
        self.network_count = network_count
        self.file_count = file_count
        self.registry_count = registry_count
        self.safelisted = safelisted

        if not signatures:
            self.signatures = {}
        else:
            self.signatures = signatures
        if not children:
            self.children = []
        else:
            self.children = children

    def add_signature(self, name: str, score: int):
        self.signatures[name] = score

    def add_child_process(self, process: ProcessItem):
        self.children.append(process)

    def add_network_events(self, val: int = 1):
        if val < 0:
            raise ValueError(f"Number of network events {val} to add must be >= 0")
        self.network_count += val

    def add_file_events(self, val: int = 1):
        if val < 0:
            raise ValueError(f"Number of file events {val} to add must be >= 0")
        self.file_count += val

    def add_registry_events(self, val: int = 1):
        if val < 0:
            raise ValueError(f"Number of registry events {val} to add must be >= 0")
        self.registry_count += val

    def safelist(self):
        self.safelisted = True

    def as_primitives(self):
        return {
            "process_pid": self.pid,
            "process_name": self.name,
            "command_line": self.cmd,
            "signatures": self.signatures,
            "children": [c.as_primitives() for c in self.children],
            "network_count": self.network_count,
            "file_count": self.file_count,
            "registry_count": self.registry_count,
            "safelisted": self.safelisted,
        }


class ProcessTreeSectionBody(SectionBody):
    def __init__(self) -> None:
        super().__init__(BODY_FORMAT.PROCESS_TREE, body=[])

    def add_process(self, process: ProcessItem) -> None:
        self._data.append(process.as_primitives())


class SandboxMachineMetadata:
    """Metadata about the machine where the sandbox analysis took place."""

    def __init__(
        self,
        # The IP of the machine used for analysis.
        ip: Optional[str] = None,

        # The hypervisor of the machine used for analysis.
        hypervisor: Optional[str] = None,

        # The name of the machine used for analysis.
        hostname: Optional[str] = None,

        # The platform of the machine used for analysis.
        platform: Optional[str] = None,

        # The version of the operating system of the machine used for analysis.
        version: Optional[str] = None,

        # The architecture of the machine used for analysis.
        architecture: Optional[str] = None,
    ):
        self.ip = ip
        self.hypervisor = hypervisor
        self.hostname = hostname
        self.platform = platform
        self.version = version
        self.architecture = architecture

    def as_primitives(self) -> Dict:
        """Return a JSON-serializable representation."""
        return {
            "ip": self.ip,
            "hypervisor": self.hypervisor,
            "hostname": self.hostname,
            "platform": self.platform,
            "version": self.version,
            "architecture": self.architecture,
        }


class SandboxAnalysisMetadata:
    """Metadata regarding the sandbox analysis task."""

    def __init__(
        self,
        # The ID used for identifying the analysis task.
        task_id: Optional[str] = None,

        # The start time of the analysis (ISO format).
        start_time: str = "",

        # The end time of the analysis (ISO format).
        end_time: Optional[str] = None,

        # The routing used in the sandbox setup. (e.g., Spoofed, Internet, Tor, VPN)
        routing: Optional[str] = None,

        # The resolution used for the analysis.
        window_size: Optional[str] = None,
    ):
        self.task_id = task_id
        self.start_time = start_time
        self.end_time = end_time
        self.routing = routing
        self.window_size = window_size

    def as_primitives(self) -> Dict:
        """Return a JSON-serializable representation."""
        return {
            "task_id": self.task_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "routing": self.routing,
            "window_size": self.window_size,
        }


class SandboxProcessItem:
    """Represents a process observed during sandbox execution."""

    def __init__(
        self,

        # The image of the process. Default: "<unknown_image>".
        image: str,

        # The time of creation for the process. (ISO date format)
        start_time: str,

        # The process ID of the parent process.
        ppid: Optional[int] = None,

        # The process ID.
        pid: Optional[int] = None,

        # The command line that the process ran.
        command_line: Optional[str] = None,

        # The time of termination for the process. (ISO date format)
        end_time: Optional[str] = None,

        # The integrity level of the process.
        integrity_level: Optional[str] = None,

        # The hash of the file run.
        image_hash: Optional[str] = None,

        # The original name of the file.
        original_file_name: Optional[str] = None,

        # Whether this process was safelisted.
        safelisted: Optional[bool] = False,

        # Number of files this process interacted with
        file_count: int = 0,

        # Number of registries this process interacted with
        registry_count: int = 0,
    ):
        # ----------------------------
        # Core process information
        # ----------------------------
        self.image = image or "<unknown_image>"
        self.start_time = start_time

        # Parent process information
        self.ppid = ppid

        # Current process information
        self.pid = pid
        self.command_line = command_line
        self.end_time = end_time
        self.integrity_level = integrity_level
        self.image_hash = image_hash
        self.original_file_name = original_file_name
        self.safelisted = safelisted

        # ----------------------------
        # Relationships & statistics
        # ----------------------------
        self.file_count = file_count
        self.registry_count = registry_count

    def as_primitives(self) -> Dict:
        """Return a JSON-serializable dictionary representation of this process."""
        return {
            "image": self.image,
            "start_time": self.start_time,
            "ppid": self.ppid,
            "pid": self.pid,
            "command_line": self.command_line,
            "end_time": self.end_time,
            "integrity_level": self.integrity_level,
            "image_hash": self.image_hash,
            "original_file_name": self.original_file_name,
            "safelisted": self.safelisted,
            "file_count": self.file_count,
            "registry_count": self.registry_count,
        }


LookupType = Literal[
    "A", "AAAA", "AFSDB", "APL", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME", "CSYNC",
    "DHCID", "DLV", "DNAME", "DNSKEY", "DS", "EUI48", "EUI64", "HINFO", "HIP",
    "HTTPS", "IPSECKEY", "KEY", "KX", "LOC", "MX", "NAPTR", "NS", "NSEC", "NSEC3",
    "NSEC3PARAM", "OPENPGPKEY", "PTR", "RRSIG", "RP", "SIG", "SMIMEA", "SOA",
    "SRV", "SSHFP", "SVCB", "TA", "TKEY", "TLSA", "TSIG", "TXT", "URI", "ZONEMD"
]

RequestMethod = Literal[
    "GET", "POST", "PUT", "DELETE", "HEAD", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    "BCOPY", "BDELETE", "BMOVE", "BPROPFIND", "BPROPPATCH", "COPY", "LOCK",
    "MKCOL", "MOVE", "NOTIFY", "POLL", "PROPFIND", "PROPPATCH", "SEARCH",
    "SUBSCRIBE", "UNLOCK", "UNSUBSCRIBE", "X-MS-ENUMATTS"
]

ConnectionType = Literal["http", "dns", "tls", "smtp"]

ConnectionDirection = Literal["outbound", "inbound", "unknown"]


class SandboxNetworkDNS:
    """Details for a DNS request."""

    def __init__(
        self,
        domain: str,
        lookup_type: LookupType,
        resolved_ips: Optional[List[str]] = None,
        resolved_domains: Optional[List[str]] = None,
    ):
        # The domain requested.
        self.domain = domain

        # A list of IPs that were resolved.
        self.resolved_ips = resolved_ips or []

        # A list of domains that were resolved.
        self.resolved_domains = resolved_domains or []

        # The type of DNS request.
        self.lookup_type = lookup_type

    def as_primitives(self) -> Dict:
        return {
            "domain": self.domain,
            "resolved_ips": self.resolved_ips,
            "resolved_domains": self.resolved_domains,
            "lookup_type": self.lookup_type,
        }


class SandboxNetworkHTTP:
    """Details for an HTTP request."""

    def __init__(
        self,
        request_uri: str,
        request_headers: Optional[Dict[str, object]] = None,
        request_method: Optional[RequestMethod] = None,
        response_headers: Optional[Dict[str, object]] = None,
        request_body: Optional[str] = None,
        response_status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        response_content_fileinfo: Optional[Dict] = None,
        response_content_mimetype: Optional[str] = None,
    ):
        # The URI requested.
        self.request_uri = request_uri

        # Headers included in the request.
        self.request_headers = request_headers or {}

        # The method of the request.
        self.request_method = request_method

        # Headers included in the response.
        self.response_headers = response_headers or {}

        # The body of the request.
        self.request_body = request_body

        # The status code of the response.
        self.response_status_code = response_status_code

        # The body of the response.
        self.response_body = response_body

        # File information of the response content.
        self.response_content_fileinfo = response_content_fileinfo

        # MIME type returned by the server.
        self.response_content_mimetype = response_content_mimetype

    def as_primitives(self) -> Dict:
        return {
            "request_uri": self.request_uri,
            "request_headers": self.request_headers,
            "request_method": self.request_method,
            "response_headers": self.response_headers,
            "request_body": self.request_body,
            "response_status_code": self.response_status_code,
            "response_body": self.response_body,
            "response_content_fileinfo": self.response_content_fileinfo,
            "response_content_mimetype": self.response_content_mimetype,
        }


class SandboxNetworkSMTP:
    """Details for an SMTP request."""

    def __init__(
        self,
        mail_from: str,
        mail_to: List[str],
        attachments: Optional[List[Dict]] = None,
    ):
        # Sender of the email.
        self.mail_from = mail_from

        # Recipients of the email.
        self.mail_to = mail_to

        # File information about the attachments.
        self.attachments = attachments or []

    def as_primitives(self) -> Dict:
        return {
            "mail_from": self.mail_from,
            "mail_to": self.mail_to,
            "attachments": self.attachments,
        }


class SandboxNetflowItem:
    """Details about a low-level network connection by IP."""

    def __init__(
        self,

        # The destination IP of the connection.
        destination_ip: Optional[str] = None,

        # The destination port of the connection.
        destination_port: Optional[int] = None,

        # The transport layer protocol (e.g., tcp, udp).
        transport_layer_protocol: Optional[Literal["tcp", "udp"]] = None,

        # The direction of the network connection.
        direction: Optional[ConnectionDirection] = None,

        # PID of the process that spawned the network connection.
        pid: Optional[int] = None,

        # The source IP of the connection.
        source_ip: Optional[str] = None,

        # The source port of the connection.
        source_port: Optional[int] = None,

        time_observed: str = None,

        # HTTP-specific details of the request.
        http_details: Optional[SandboxNetworkHTTP] = None,

        # DNS-specific details of the request.
        dns_details: Optional[SandboxNetworkDNS] = None,

        # SMTP-specific details of the request.
        smtp_details: Optional[SandboxNetworkSMTP] = None,

        # Type of connection being made.
        connection_type: Optional[ConnectionType] = None,
    ):
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.transport_layer_protocol = transport_layer_protocol
        self.direction = direction
        self.pid = pid
        self.source_ip = source_ip
        self.source_port = source_port
        self.time_observed = time_observed
        self.http_details = http_details
        self.dns_details = dns_details
        self.smtp_details = smtp_details
        self.connection_type = connection_type

    def as_primitives(self) -> Dict:
        """Return a JSON-serializable representation."""
        data: Dict[str, Any] = {
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "transport_layer_protocol": self.transport_layer_protocol,
            "direction": self.direction,
            "pid": self.pid,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "time_observed": self.time_observed,
            "connection_type": self.connection_type,
        }

        if self.http_details is not None:
            data["http_details"] = self.http_details.as_primitives()

        if self.dns_details is not None:
            data["dns_details"] = self.dns_details.as_primitives()

        if self.smtp_details is not None:
            data["smtp_details"] = self.smtp_details.as_primitives()

        return data


class SandboxAttackItem:
    """Represents a MITRE ATT&CK technique or pattern."""

    def __init__(
        self,
        attack_id: str,
        pattern: str = None,
        categories: List[str] = [],
    ):
        self.attack_id = attack_id
        self.pattern = pattern
        self.categories = categories or []

    def as_primitives(self) -> Dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "pattern": self.pattern,
            "categories": self.categories,
        }


class SandboxSignatureItem:
    """A signature that was raised during the analysis of the task."""

    def __init__(
        self,

        # The name of the signature.
        name: str,

        # Type of signature. One of: "CUCKOO", "YARA", "SIGMA", "SURICATA".
        type: Literal["CUCKOO", "YARA", "SIGMA", "SURICATA"],

        # Classification of signature (e.g., "malicious", "benign").
        classification: str,

        # A list of ATT&CK patterns and categories of the signature.
        attacks: Optional[List[SandboxAttackItem]] = [],

        # List of actors of the signature.
        actors: Optional[List[str]] = [],

        # List of malware families of the signature.
        malware_families: Optional[List[str]] = [],

        # ID of the signature.
        signature_id: Optional[str] = None,

        # Optional human-readable message.
        message: Optional[str] = None,

        # PID of the process that generated the signature.
        pid: Optional[int] = None,

        # ID of the heuristic this signature belongs to
        heuristic: str = None,
    ):
        self.name = name
        self.type = type
        self.classification = classification
        self.attacks = attacks
        self.actors = actors
        self.malware_families = malware_families
        self.signature_id = signature_id
        self.message = message
        self.pid = pid
        self.heuristic = heuristic

    def as_primitives(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "classification": self.classification,
            "attacks": [a.as_primitives() for a in self.attacks] if self.attacks else None,
            "actors": self.actors,
            "malware_families": self.malware_families,
            "signature_id": self.signature_id,
            "message": self.message,
            "pid": self.pid,
            "heuristic": self.heuristic,
        }


class SandboxHeuristicItem:
    """
    Represents a raised heuristic during sandbox analysis.
    """

    def __init__(
        self,
        # Heuristic ID
        heur_id: str,

        # Score associated with this heuristic
        score: int,

        # Name of the heuristic
        name: str,

        # Tags associated with this heuristic
        tags: Optional[Dict[str, List[Any]]] = None,
    ):
        self.heur_id = heur_id
        self.score = score
        self.name = name
        self.tags = tags or {}

    def as_primitives(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "heur_id": self.heur_id,
            "score": self.score,
            "name": self.name,
            "tags": self.tags,
        }


class SandboxSectionBody(SectionBody):
    """
    Represents the structured body of a sandbox analysis section.
    Collects all sandbox-relevant entities: sandbox metadata, processes, network flows, and signatures.
    """

    def __init__(self) -> None:
        super().__init__(BODY_FORMAT.SANDBOX, body={
            "sandbox_name": None,
            "sandbox_version": None,
            "machine_metadata": None,
            "analysis_metadata": None,
            "processes": [],
            "netflows": [],
            "signatures": [],
            "heuristics": [],
        })

    def set_sandbox(self, name: str, version: Optional[str], machine_metadata: SandboxMachineMetadata, analysis_metadata: SandboxAnalysisMetadata) -> None:
        """Set the sandbox metadata (name, version, machine info, and analysis info)."""
        self._data["sandbox_name"] = name
        self._data["sandbox_version"] = version
        self._data["machine_metadata"] = (
            machine_metadata.as_primitives() if machine_metadata else None
        )
        self._data["analysis_metadata"] = (
            analysis_metadata.as_primitives() if analysis_metadata else None
        )

    def add_process(self, process: SandboxProcessItem) -> None:
        """Add a single process to the sandbox result."""
        if not isinstance(process, SandboxProcessItem):
            raise TypeError("Expected SandboxProcessItem")
        self._data["processes"].append(process.as_primitives())

    def add_processes(self, processes: List[SandboxProcessItem]) -> None:
        """Add multiple processes at once."""
        for proc in processes:
            self.add_process(proc)

    def add_netflow(self, netflow: SandboxNetflowItem) -> None:
        """Add a network flow to the sandbox result."""
        if not isinstance(netflow, SandboxNetflowItem):
            raise TypeError("Expected SandboxNetflowItem")
        self._data["netflows"].append(netflow.as_primitives())

    def add_netflows(self, netflows: List[SandboxNetflowItem]) -> None:
        """Add multiple network flows at once."""
        for nf in netflows:
            self.add_netflow(nf)

    def add_signature(self, signature: SandboxSignatureItem) -> None:
        """Add a detection signature to the sandbox result."""
        if not isinstance(signature, SandboxSignatureItem):
            raise TypeError("Expected SandboxSignatureItem")
        self._data["signatures"].append(signature.as_primitives())

    def add_signatures(self, signatures: List[SandboxSignatureItem]) -> None:
        """Add multiple detection signatures at once."""
        for sig in signatures:
            self.add_signature(sig)

    def add_heuristic(self, heuristic: SandboxHeuristicItem) -> None:
        """Add a heuristic to the sandbox result."""
        if not isinstance(heuristic, SandboxHeuristicItem):
            raise TypeError("Expected SandboxHeuristicItem")
        self._data["heuristics"].append(heuristic.as_primitives())

    def add_heuristics(self, heuristics: List[SandboxHeuristicItem]) -> None:
        """Add multiple heuristics at once."""
        for h in heuristics:
            self.add_heuristic(h)

    def as_primitives(self) -> Dict[str, Any]:
        """Return a fully JSON-serializable structure."""
        return {
            "sandbox_name": self._data["sandbox_name"],
            "sandbox_version": self._data["sandbox_version"],
            "machine_metadata": self._data["machine_metadata"],
            "analysis_metadata": self._data["analysis_metadata"],
            "processes": self._data["processes"],
            "netflows": self._data["netflows"],
            "signatures": self._data["signatures"],
            "heuristics": self._data["heuristics"],
        }


class TableRow(dict):
    def __init__(self, *args, **kwargs) -> None:
        data = {}
        for arg in args:
            data.update(arg)
        data.update(kwargs)
        super().__init__(**data)


class TableSectionBody(SectionBody):
    def __init__(self) -> None:
        super().__init__(BODY_FORMAT.TABLE, body=[])

    def add_row(self, row: TableRow) -> None:
        if row == {}:
            return

        self._data.append(row)
        self.set_column_order(list(row.keys()))

    def set_column_order(self, order: List[str]) -> None:
        if not order:
            return

        self._config = {'column_order': order}


class ImageSectionBody(SectionBody):
    def __init__(self, request: ServiceRequest) -> None:
        self._request = request
        super().__init__(BODY_FORMAT.IMAGE, body=[])

    def add_image(self, path: str, name: str, description: str,
                  classification: Optional[Classification] = None,
                  ocr_heuristic_id: Optional[int] = None, ocr_io: Optional[TextIO] = None) -> Optional[ResultSection]:
        res = self._request.add_image(path, name, description, classification, ocr_heuristic_id, ocr_io)
        ocr_section = res.pop('ocr_section', None)
        self._data.append(res)

        return ocr_section


class MultiSectionBody(SectionBody):
    def __init__(self) -> None:
        super().__init__(BODY_FORMAT.MULTI, body=[])

    # Note that this method is named differently than the method to
    # add a section body to the ResultMultiSection (add_section_part)
    def add_section_body(self, section_body: SectionBody) -> None:
        self._data.append((section_body.format, section_body._data, section_body._config))


class DividerSectionBody(SectionBody):
    def __init__(self) -> None:
        super().__init__(BODY_FORMAT.DIVIDER, body=None)


class TimelineSectionBody(SectionBody):
    def __init__(self):
        super().__init__(BODY_FORMAT.TIMELINE, body=[])

    def add_node(self, title: str, content: str, opposite_content: str,
                 icon: str = None, signatures: List[str] = [], score: int = 0) -> None:
        self._data.append(dict(title=title, content=content, opposite_content=opposite_content,
                               icon=icon, signatures=signatures, score=score))


class ResultSection:
    def __init__(
            self,
            title_text: Union[str, List],
            body: Optional[Union[str, SectionBody]] = None,
            classification: Optional[Classification] = None,
            body_format=BODY_FORMAT.TEXT,
            heuristic: Optional[Heuristic] = None,
            tags: Optional[Dict[str, List[str]]] = None,
            parent: Optional[Union[ResultSection, Result]] = None,
            zeroize_on_tag_safe: bool = False,
            auto_collapse: bool = False,
            zeroize_on_sig_safe: bool = True,
    ):
        # Lazy load service attributes
        global SERVICE_ATTRIBUTES
        if not SERVICE_ATTRIBUTES:
            SERVICE_ATTRIBUTES = get_service_attributes()

        self._finalized: bool = False
        self.parent = parent
        self._section = None
        self._subsections: List[ResultSection] = []
        if isinstance(body, SectionBody):
            self._body_format = body.format
            self._body_config = body.config
            self._body = body.body
        else:
            self._body_format = body_format
            self._body = body
            self._body_config = {}
        self.classification: Classification = classification or SERVICE_ATTRIBUTES.default_result_classification
        self.depth: int = 0
        self._tags = tags or {}
        self._heuristic = None
        self.zeroize_on_tag_safe = zeroize_on_tag_safe
        self.auto_collapse = auto_collapse
        self.zeroize_on_sig_safe = zeroize_on_sig_safe
        self._promote_to = None

        if isinstance(title_text, list):
            title_text = ''.join(title_text)
        self.title_text = safe_str(title_text)

        if heuristic:
            if not isinstance(heuristic, Heuristic):
                log.warning(f"This is not a valid Heuristic object: {str(heuristic)}")
            else:
                self._heuristic = heuristic

        if parent is not None:
            if isinstance(parent, ResultSection):
                parent.add_subsection(self)
            elif isinstance(parent, Result):
                parent.add_section(self)

    @property
    def body(self):
        return self._body

    @property
    def body_format(self):
        return self._body_format

    @property
    def body_config(self):
        return self._body_config

    @property
    def heuristic(self):
        return self._heuristic

    @property
    def promote_to(self):
        return self._promote_to

    @property
    def subsections(self):
        return self._subsections

    @property
    def tags(self):
        return self._tags

    def add_line(self, text: Union[str, List[str]]) -> None:
        # add_line with a list should join without newline seperator.
        # use add_lines if list should be split one element per line.
        if text is None:
            raise ValueError("Expected text to add to a line must be a string or a list, not None.")

        if isinstance(text, list):
            text = ''.join(text)
        textstr = safe_str(text)
        if self._body:
            textstr = '\n' + textstr
            self._body = self._body + textstr
        else:
            self._body = textstr

    def add_lines(self, line_list: List[str]) -> None:
        if not isinstance(line_list, list):
            log.warning(f"add_lines called with invalid type: {type(line_list)}. ignoring")
            return

        segment = '\n'.join(line_list)
        if self._body is None:
            self._body = segment
        else:
            self._body = self._body + '\n' + segment

    def add_subsection(self, subsection: ResultSection, on_top: bool = False) -> None:
        """
        Add a result subsection to another result section or subsection.

        :param subsection: Subsection to add to another result section or subsection
        :param on_top: Display this result section on top of other subsections
        """
        if on_top:
            self._subsections.insert(0, subsection)
        else:
            self._subsections.append(subsection)
        subsection.parent = self

    def add_tag(self, tag_type: str, value: Union[str, bytes]) -> None:
        if not tag_type:
            return

        if isinstance(value, bytes):
            value = value.decode()

        if value == "":
            return

        if tag_type not in self._tags:
            self._tags[tag_type] = []

        if value not in self._tags[tag_type]:
            self._tags[tag_type].append(value)

    def finalize(self, depth: int = 0) -> bool:
        if self._finalized:
            raise ResultAggregationException("Double finalize() on result detected.")

        if not self.title_text:
            log.error("Failed to finalize section, title is empty...")
            return False

        # Catch body values that are not None, but are not "valid" such as empty strings/lists/dicts/etc
        if not self.body and self.body is not None:
            self._body = None

        self._finalized = True

        tmp_subs: List[ResultSection] = []
        self.depth = depth
        for subsection in self._subsections:
            if subsection.finalize(depth=depth+1):
                tmp_subs.append(subsection)
        self._subsections = tmp_subs

        return True

    def set_body(self, body: Union[str, SectionBody], body_format: str = None) -> None:
        if isinstance(body, SectionBody):
            self._body = body.body
            self._body_format = body._format
        else:
            self._body = body
            if body_format:
                self._body_format = body_format

    def set_heuristic(
            self, heur: Union[int, Heuristic, None],
            attack_id: Optional[str] = None, signature: Optional[str] = None) -> None:
        """
        Set a heuristic for a result section/subsection.
        A heuristic is required to assign a score to a result section/subsection.

        :param heur: Heuristic ID as set in the service manifest or Heuristic Instance
        :param attack_id: (optional) Attack ID related to the heuristic
        :param signature: (optional) Signature Name that triggered the heuristic
        """
        if heur is None:
            self._heuristic = None
        elif self._heuristic:
            heur_id = heur.heur_id if isinstance(heur, Heuristic) else heur
            raise InvalidHeuristicException(f"The service is trying to set the heuristic twice, this is not allowed. "
                                            f"[Current: {self.heuristic.heur_id}, New: {heur_id}]")
        elif isinstance(heur, Heuristic):
            self._heuristic = heur
        # at this point, heur is an integer representing a heuristic ID
        else:
            self._heuristic = Heuristic(heur)

        # Only get here if a new heuristic is set
        if self._heuristic:
            if attack_id:
                self._heuristic.add_attack_id(attack_id)
            if signature:
                self._heuristic.add_signature_id(signature)

    def set_tags(self, tags: Dict[str, List[Union[str, bytes]]]) -> None:
        if not isinstance(tags, dict):
            return

        self._tags = tags


class TypeSpecificResultSection(ResultSection):
    def __init__(self, title_text: Union[str, List], section_body: SectionBody, **kwargs):
        # Not allowed to specified body_format since it will come from the section body
        kwargs.pop('body_format', None)
        kwargs.pop('body', None)

        self.section_body = section_body
        super().__init__(title_text, body_format=self.section_body.format, **kwargs)

    @property
    def body(self):
        return self.section_body.body

    @property
    def body_config(self):
        return self.section_body.config

    def add_line(self, text: Union[str, List]) -> None:
        raise InvalidFunctionException("Do not use default add_line method in a type-specific section.")

    def add_lines(self, line_list: List[str]) -> None:
        raise InvalidFunctionException("Do not use default add_lines method in a type-specific section.")

    def set_body(self, body: Union[str, SectionBody], body_format=BODY_FORMAT.TEXT) -> None:
        raise InvalidFunctionException("Do not use default set_body method in a type-specific section.")


class ResultTextSection(ResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        # Not allowed to specified body_format since locked to TEXT
        kwargs.pop('body_format', None)
        super().__init__(title_text, body_format=BODY_FORMAT.TEXT, **kwargs)


class ResultMemoryDumpSection(ResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        # Not allowed to specified body_format since locked to MEMORY_DUMP
        kwargs.pop('body_format', None)
        super().__init__(title_text, body_format=BODY_FORMAT.MEMORY_DUMP, **kwargs)


class ResultGraphSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        self.section_body: GraphSectionBody
        super().__init__(title_text, GraphSectionBody(), **kwargs)

    def set_colormap(self, cmap_min: int, cmap_max: int, values: List[int]) -> None:
        self.section_body.set_colormap(cmap_min, cmap_max, values)

    def promote_as_entropy(self):
        self._promote_to = PROMOTE_TO.ENTROPY


class ResultURLSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        self.section_body: URLSectionBody
        super().__init__(title_text, URLSectionBody(), **kwargs)

    def add_url(self, url: str, name: Optional[str] = None) -> None:
        self.section_body.add_url(url, name=name)


class ResultKeyValueSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], body: dict[str, KV_VALUE_TYPE] | None = None, **kwargs):
        self.section_body: KVSectionBody
        super().__init__(title_text, KVSectionBody(**(body if body else {})), **kwargs)

    def set_item(self, key: str, value: Union[str, bool, int]) -> None:
        self.section_body.set_item(key, value)

    def update_items(self, new_dict):
        self.section_body.update_items(new_dict)

    def promote_as_uri_params(self):
        self._promote_to = PROMOTE_TO.URI_PARAMS


class ResultOrderedKeyValueSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], body: dict[str, KV_VALUE_TYPE] | None = None, **kwargs):
        self.section_body: OrderedKVSectionBody
        super().__init__(title_text, OrderedKVSectionBody(**(body if body else {})), **kwargs)

    def add_item(self, key: str, value: Union[str, bool, int]) -> None:
        self.section_body.add_item(key, value)

    def promote_as_uri_params(self):
        self._promote_to = PROMOTE_TO.URI_PARAMS


class ResultJSONSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        self.section_body: JSONSectionBody
        super().__init__(title_text, JSONSectionBody(), **kwargs)

    def set_json(self, json_body: dict) -> None:
        self.section_body.set_json(json_body)

    def update_json(self, json_body: dict) -> None:
        self.section_body.update_json(json_body)


class ResultProcessTreeSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        self.section_body: ProcessTreeSectionBody
        super().__init__(title_text, ProcessTreeSectionBody(), **kwargs)

    def add_process(self, process: ProcessItem) -> None:
        self.section_body.add_process(process)


class ResultSandboxSection(TypeSpecificResultSection):
    """
    Represents a result section specifically designed for sandbox analysis data.
    Provides a typed interface to manipulate the underlying SandboxSectionBody.
    """

    def __init__(self, title_text: Union[str, List], **kwargs):
        self.section_body: SandboxSectionBody
        super().__init__(title_text, SandboxSectionBody(), **kwargs)

    def set_sandbox(
        self,
        name: str,
        version: Optional[str],
        machine_metadata: Optional[SandboxMachineMetadata],
        analysis_metadata: Optional[SandboxAnalysisMetadata],
    ) -> None:
        """Set the sandbox metadata (name, version, machine info, and analysis info)."""
        self.section_body.set_sandbox(name, version, machine_metadata, analysis_metadata)

    def add_process(self, process: SandboxProcessItem) -> None:
        """Add a single process to the sandbox result."""
        self.section_body.add_process(process)

    def add_processes(self, processes: List[SandboxProcessItem]) -> None:
        """Add multiple processes at once."""
        self.section_body.add_processes(processes)

    def add_netflow(self, netflow: SandboxNetflowItem) -> None:
        """Add a single network flow to the sandbox result."""
        self.section_body.add_netflow(netflow)

    def add_netflows(self, netflows: List[SandboxNetflowItem]) -> None:
        """Add multiple network flows at once."""
        self.section_body.add_netflows(netflows)

    def add_signature(self, signature: SandboxSignatureItem) -> None:
        """Add a detection signature to the sandbox result."""
        self.section_body.add_signature(signature)

    def add_signatures(self, signatures: List[SandboxSignatureItem]) -> None:
        """Add multiple detection signatures at once."""
        self.section_body.add_signatures(signatures)

    def add_heuristic(self, heuristic: SandboxHeuristicItem) -> None:
        """Add a heuristic to the sandbox result."""
        self.section_body.add_heuristic(heuristic)

    def add_heuristics(self, heuristics: List[SandboxHeuristicItem]) -> None:
        """Add multiple heuristics at once."""
        self.section_body.add_heuristics(heuristics)


class ResultTableSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        self.section_body: TableSectionBody
        super().__init__(title_text, TableSectionBody(), **kwargs)

    def add_row(self, row: TableRow) -> None:
        self.section_body.add_row(row)
        self.set_column_order(list(row.keys()))

    def set_column_order(self, order: List[str]):
        self.section_body.set_column_order(order)


class ResultImageSection(TypeSpecificResultSection):
    def __init__(self, request: ServiceRequest, title_text: Union[str, List], **kwargs) -> None:
        self.section_body: ImageSectionBody
        super().__init__(title_text, ImageSectionBody(request), **kwargs)

    def add_image(self, path: str, name: str, description: str,
                  classification: Optional[Classification] = None,
                  ocr_heuristic_id: Optional[int] = None,
                  ocr_io: Optional[TextIO] = None,
                  auto_add_ocr_section: bool = True) -> Optional[ResultSection]:

        ocr_section = self.section_body.add_image(path, name, description, classification, ocr_heuristic_id, ocr_io)
        if ocr_section and auto_add_ocr_section:
            self.add_subsection(ocr_section)
            return None

        return ocr_section

    def promote_as_screenshot(self):
        self._promote_to = PROMOTE_TO.SCREENSHOT


class ResultTimelineSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        self.section_body: TimelineSectionBody
        super().__init__(title_text, TimelineSectionBody(), **kwargs)

    def add_node(self, title: str, content: str, opposite_content: str, icon: str = None, signatures: List[str] = [],
                 score: int = 0) -> None:
        self.section_body.add_node(title=title, content=content, opposite_content=opposite_content,
                                   icon=icon, signatures=signatures, score=score)


class ResultMultiSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        self.section_body: MultiSectionBody
        super().__init__(title_text, MultiSectionBody(), **kwargs)

    # Note that this method is named differently than the method to
    # add a section body to the MultiSectionBody (add_section_body)
    def add_section_part(self, section_part: SectionBody) -> None:
        self.section_body.add_section_body(section_part)


class Result:
    def __init__(self, sections: Optional[List[ResultSection]] = None) -> None:
        self._flattened_sections: List[Dict[str, Any]] = []
        self._score: int = 0
        self.sections: List[ResultSection] = sections or []

    def _append_section(self, section: ResultSection) -> None:
        self._flattened_sections.append(dict(
            body=section.body,
            classification=section.classification,
            body_format=section.body_format,
            body_config=section.body_config,
            depth=section.depth,
            heuristic=get_heuristic_primitives(section.heuristic),
            tags=unflatten(section.tags),
            title_text=section.title_text,
            zeroize_on_tag_safe=section.zeroize_on_tag_safe,
            auto_collapse=section.auto_collapse,
            promote_to=section.promote_to
        ))

    def _flatten_sections(self, section: ResultSection, root: bool = True) -> None:
        if len(section.subsections) > 0:
            if root:
                self._append_section(section)

            for subsection in section.subsections:
                self._append_section(subsection)
                if len(subsection.subsections) > 0:
                    self._flatten_sections(subsection, root=False)
        else:
            self._append_section(section)

    def add_section(self, section: ResultSection, on_top: bool = False) -> None:
        """
        Add a result section to the root of the result.

        :param section: Section to add to the root of the result
        :param on_top: Display this result section on top of other sections
        """
        if on_top:
            self.sections.insert(0, section)
        else:
            self.sections.append(section)

    def finalize(self) -> Dict[str, Any]:
        to_delete_sections = []

        for section in self.sections:
            section.parent = self
            if not section.finalize():
                to_delete_sections.append(section)

        # Delete sections we can't keep
        for section in to_delete_sections:
            self.sections.remove(section)

        # Flatten all the sections into a flat list
        for section in self.sections:
            self._flatten_sections(section)

        for flattened_section in self._flattened_sections:
            heuristic = flattened_section.get('heuristic')
            if heuristic:
                self._score += heuristic['score']

        result = dict(
            score=self._score,
            sections=self._flattened_sections,
        )

        return result
