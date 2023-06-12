from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, TextIO, Union

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
    ('TIMELINE', 12)
])


class InvalidHeuristicException(Exception):
    pass


class InvalidFunctionException(Exception):
    pass


class ResultAggregationException(Exception):
    pass


def get_heuristic_primitives(heur: Heuristic):
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
            return json.dumps(self._data)
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

    def add_line(self, text: Union[str, List]) -> None:
        # add_line with a list should join without newline seperator.
        # use add_lines if list should be split one element per line.
        if isinstance(text, list):
            text = ''.join(text)
        textstr = safe_str(text)
        if self._data:
            self._data = f"{self._data}\n{textstr}"
        else:
            self._data = textstr
        return self._data

    def add_lines(self, line_list: List[str]) -> None:
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

    def update_items(self, new_dict: dict[str, KV_VALUE_TYPE]):
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
        self._data.append(row)
        self.set_column_order(list(row.keys()))

    def set_column_order(self, order: List[str]):
        self._config = {'column_order': order}



class ImageSectionBody(SectionBody):
    def __init__(self, request: ServiceRequest) -> None:
        self._request = request
        super().__init__(BODY_FORMAT.IMAGE, body=[])

    def add_image(self, path: str, name: str, description: str,
                  classification: Optional[Classification] = None,
                  ocr_heuristic_id: Optional[int] = None, ocr_io: Optional[TextIO] = None) -> Optional[ResultSection]:
        res = self._request.add_image(path, name, description, classification, ocr_heuristic_id, ocr_io)
        sections = res.pop('ocr_section', None)
        self._data.append(res)

        return sections


class MultiSectionBody(SectionBody):
    def __init__(self) -> None:
        super().__init__(BODY_FORMAT.MULTI, body=[])

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
    def subsections(self):
        return self._subsections

    @property
    def tags(self):
        return self._tags

    def add_line(self, text: Union[str, List]) -> None:
        # add_line with a list should join without newline seperator.
        # use add_lines if list should be split one element per line.
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
        if isinstance(value, bytes):
            value = value.decode()

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

        if not self.body and self.body is not None:
            self._body = None

        self._finalized = True

        tmp_subs = []
        self.depth = depth
        for subsection in self._subsections:
            if subsection.finalize(depth=depth+1):
                tmp_subs.append(subsection)
        self._subsections = tmp_subs

        return True

    def set_body(self, body: Union[str, SectionBody], body_format=None) -> None:
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
            if attack_id:
                heur.add_attack_id(attack_id)
            if signature:
                heur.add_signature_id(signature)
            self._heuristic = heur
        else:
            self._heuristic = Heuristic(heur, attack_id=attack_id, signature=signature)

    def set_tags(self, tags: Dict[str, List[Union[str, bytes]]]):
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
        raise InvalidFunctionException("Do not use default add_line method in a type specific section.")

    def add_lines(self, line_list: List[str]) -> None:
        raise InvalidFunctionException("Do not use default add_lines method in a type specific section.")

    def set_body(self, body: Union[str, SectionBody], body_format=BODY_FORMAT.TEXT) -> None:
        raise InvalidFunctionException("Do not use default set_body method in a type specific section.")


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
    def __init__(self, title_text: Union[str, List],  **kwargs):
        self.section_body: GraphSectionBody
        super().__init__(title_text, GraphSectionBody(), **kwargs)

    def set_colormap(self, cmap_min: int, cmap_max: int, values: List[int]) -> None:
        self.section_body.set_colormap(cmap_min, cmap_max, values)


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


class ResultOrderedKeyValueSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], body: dict[str, KV_VALUE_TYPE] | None = None, **kwargs):
        self.section_body: OrderedKVSectionBody
        super().__init__(title_text, OrderedKVSectionBody(**(body if body else {})), **kwargs)

    def add_item(self, key: str, value: Union[str, bool, int]) -> None:
        self.section_body.add_item(key, value)


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


class ResultTimelineSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        self.section_body: TimelineSectionBody
        super().__init__(title_text,  TimelineSectionBody(), **kwargs)

    def add_node(self, title: str, content: str, opposite_content: str, icon: str = None, signatures: List[str] = [],
                 score: int = 0) -> None:
        self.section_body.add_node(title=title, content=content, opposite_content=opposite_content,
                                   icon=icon, signatures=signatures, score=score)


class ResultMultiSection(TypeSpecificResultSection):
    def __init__(self, title_text: Union[str, List], **kwargs):
        self.section_body: MultiSectionBody
        super().__init__(title_text,  MultiSectionBody(), **kwargs)

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
            auto_collapse=section.auto_collapse
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
