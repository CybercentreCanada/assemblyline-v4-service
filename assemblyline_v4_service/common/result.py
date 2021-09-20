from __future__ import annotations

import logging
from typing import List, Union, Optional, Dict, Any

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.common.attack_map import attack_map, software_map, group_map, revoke_map
from assemblyline.common.dict_utils import unflatten
from assemblyline.common.str_utils import StringTable, safe_str
from assemblyline_v4_service.common.helper import get_service_attributes, get_heuristics

al_log.init_logging('service.result')
log = logging.getLogger('assemblyline.service.result')

Classification = forge.get_classification()
SERVICE_ATTRIBUTES = get_service_attributes()

BODY_FORMAT = StringTable('BODY_FORMAT', [
    ('TEXT', 0),
    ('MEMORY_DUMP', 1),
    ('GRAPH_DATA', 2),
    ('URL', 3),
    ('JSON', 4),
    ('KEY_VALUE', 5),
    ('PROCESS_TREE', 6),
    ('TABLE', 7),
])


class InvalidHeuristicException(Exception):
    pass


class ResultAggregationException(Exception):
    pass


HEUR_LIST = get_heuristics()


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
                 signatures: Optional[Dict[(str, None), int]] = None,
                 frequency: Optional[int] = 1,
                 score_map: Optional[Dict[str, int]] = None):

        # Validate heuristic
        if heur_id not in HEUR_LIST:
            raise InvalidHeuristicException(f"Invalid heuristic. A heuristic with ID: {heur_id}, must be added to "
                                            f"the service manifest before using it.")

        # Set default values
        self.definition = HEUR_LIST[heur_id]
        self.heur_id = heur_id
        self.attack_ids = []
        self.frequency = 0

        # Live score map is either score_map or an empty map
        self.score_map = score_map or {}

        # Default attack_id list is either empty or received attack_ids parameter
        attack_ids = attack_ids or []

        # If an attack_id is specified, append it to attack id list
        if attack_id:
            attack_ids.append(attack_id)

        # If no attack_id are set, check heuristic definition for a default attack id
        if not attack_ids and self.definition.attack_id:
            attack_ids.extend(self.definition.attack_id)

        # Validate that all attack_ids are in the attack_map
        for a_id in attack_ids:
            if a_id in attack_map or a_id in software_map or a_id in group_map:
                self.attack_ids.append(a_id)
            elif a_id in revoke_map:
                self.attack_ids.append(revoke_map[a_id])
            else:
                log.warning(f"Invalid attack_id '{a_id}' for heuristic '{heur_id}'. Ignoring it.")

        # Signature map is either the provided value or an empty map
        self.signatures = signatures or {}

        # If a signature is provided, add it to the map and increment its frequency
        if signature:
            self.signatures.setdefault(signature, 0)
            self.signatures[signature] += frequency

        # If there are no signatures, add an empty signature with frequency of one (signatures drives the score)
        if not self.signatures:
            self.frequency = frequency

    @property
    def score(self):
        temp_score = 0
        if len(self.signatures) > 0:
            # There are signatures associated to the heuristic, loop through them and compute a score
            for sig_name, freq in self.signatures.items():
                # Find which score we should use for this signature (In order of importance)
                #   1. Heuristic's signature score map
                #   2. Live service submitted score map
                #   3. Heuristic's default signature
                sig_score = self.definition.signature_score_map.get(sig_name,
                                                                    self.score_map.get(sig_name,
                                                                                       self.definition.score))
                temp_score += sig_score * freq
        else:
            # There are no signatures associated to the heuristic, compute the new score based of that new frequency
            frequency = self.frequency or 1
            temp_score = self.definition.score * frequency

        # Checking score boundaries
        if self.definition.max_score:
            temp_score = min(temp_score, self.definition.max_score)

        return temp_score

    def add_attack_id(self, attack_id: str):
        if attack_id not in self.attack_ids:
            if attack_id in attack_map or attack_id in software_map or attack_id in group_map:
                self.attack_ids.append(attack_id)
            elif attack_id in revoke_map:
                new_attack_id = revoke_map[attack_id]
                if new_attack_id not in self.attack_ids:
                    self.attack_ids.append(new_attack_id)
            else:
                log.warning(f"Invalid attack_id '{attack_id}' for heuristic '{self.heur_id}'. Ignoring it.")

    def add_signature_id(self, signature: str, score: int = None, frequency: int = 1):
        # Add the signature to the map and adds it new frequency to the old value
        self.signatures.setdefault(signature, 0)
        self.signatures[signature] += frequency

        # If a new score is assigned to the signature save it here
        if score is not None:
            self.score_map[signature] = score

    def increment_frequency(self, frequency: int = 1):
        # Increment the signature less frequency of the heuristic
        self.frequency += frequency


class ResultSection:
    def __init__(
            self,
            title_text: Union[str, List],
            body: Optional[str, Dict] = None,
            classification: Optional[Classification] = None,
            body_format: BODY_FORMAT = BODY_FORMAT.TEXT,
            heuristic: Optional[Heuristic] = None,
            tags: Optional[Dict[str, List[str]]] = None,
            parent: Optional[Union[ResultSection, Result]] = None,
            zeroize_on_tag_safe: bool = False,
            auto_collapse: bool = False,
            zeroize_on_sig_safe: bool = True,
    ):
        self._finalized: bool = False
        self.parent = parent
        self._section = None
        self.subsections: List[ResultSection] = []
        self.body: str = body
        self.classification: Classification = classification or SERVICE_ATTRIBUTES.default_result_classification
        self.body_format: BODY_FORMAT = body_format
        self.depth: int = 0
        self.tags = tags or {}
        self.heuristic = None
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
                self.heuristic = heuristic

        if parent is not None:
            if isinstance(parent, ResultSection):
                parent.add_subsection(self)
            elif isinstance(parent, Result):
                parent.add_section(self)

    def add_line(self, text: Union[str, List]) -> None:
        # add_line with a list should join without newline seperator.
        # use add_lines if list should be split one element per line.
        if isinstance(text, list):
            text = ''.join(text)
        textstr = safe_str(text)
        if self.body:
            textstr = '\n' + textstr
            self.body = self.body + textstr
        else:
            self.body = textstr

    def add_lines(self, line_list: List[str]) -> None:
        if not isinstance(line_list, list):
            log.warning(f"add_lines called with invalid type: {type(line_list)}. ignoring")
            return

        segment = '\n'.join(line_list)
        if self.body is None:
            self.body = segment
        else:
            self.body = self.body + '\n' + segment

    def add_subsection(self, subsection: ResultSection, on_top: bool = False) -> None:
        """
        Add a result subsection to another result section or subsection.

        :param subsection: Subsection to add to another result section or subsection
        :param on_top: Display this result section on top of other subsections
        """
        if on_top:
            self.subsections.insert(0, subsection)
        else:
            self.subsections.append(subsection)
        subsection.parent = self

    def add_tag(self, tag_type: str, value: Union[str, bytes]) -> None:
        if isinstance(value, bytes):
            value = value.decode()

        if tag_type not in self.tags:
            self.tags[tag_type] = []

        if value not in self.tags[tag_type]:
            self.tags[tag_type].append(value)

    def finalize(self, depth: int = 0) -> bool:
        if self._finalized:
            raise ResultAggregationException("Double finalize() on result detected.")

        if not self.title_text:
            log.error("Failed to finalize section, title is empty...")
            return False

        if not self.body and self.body is not None:
            self.body = None

        self._finalized = True

        tmp_subs = []
        self.depth = depth
        for subsection in self.subsections:
            if subsection.finalize(depth=depth+1):
                tmp_subs.append(subsection)
        self.subsections = tmp_subs

        return True

    def set_body(self, body: str, body_format: BODY_FORMAT = BODY_FORMAT.TEXT) -> None:
        self.body = body
        self.body_format = body_format

    def set_heuristic(self, heur_id: int, attack_id: Optional[str] = None, signature: Optional[str] = None) -> None:
        """
        Set a heuristic for a result section/subsection.
        A heuristic is required to assign a score to a result section/subsection.

        :param heur_id: Heuristic ID as set in the service manifest
        :param attack_id: (optional) Attack ID related to the heuristic
        :param signature: (optional) Signature Name that triggered the heuristic
        """

        if self.heuristic:
            raise InvalidHeuristicException(f"The service is trying to set the heuristic twice, this is not allowed. "
                                            f"[Current: {self.heuristic.heur_id}, New: {heur_id}]")

        self.heuristic = Heuristic(heur_id, attack_id=attack_id, signature=signature)


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

        for section in self._flattened_sections:
            heuristic = section.get('heuristic')
            if heuristic:
                self._score += heuristic['score']

        result = dict(
            score=self._score,
            sections=self._flattened_sections,
        )

        return result
