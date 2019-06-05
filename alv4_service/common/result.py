from alv4_service.common.helper import get_classification
from assemblyline.common.str_utils import NamedConstants, StringTable
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.result import ResultBody, Section, Tag

CLASSIFICATION = get_classification()

BODY_FORMAT = StringTable('BODY_FORMAT', [
    ('TEXT', 0),
    ('MEMORY_DUMP', 1),
    ('GRAPH_DATA', 2),
    ('URL', 3),
    ('JSON', 4)
])

SCORE = NamedConstants('SCORE', [
    ('OK', -1000),  # Not malware
    ('NULL', 0),
    ('LOW', 1),
    ('MED', 10),
    ('HIGH', 100),
    ('VHIGH', 500),
    ('SURE', 1000)  # Malware
])


class ResultSection:
    def __init__(
            self,
            body='',
            classification: CLASSIFICATION = CLASSIFICATION.UNRESTRICTED,
            title_text: str or list = None,
            score=0,
            body_format: BODY_FORMAT = BODY_FORMAT.TEXT
    ):
        self._section = Section()
        self.body = body
        self.classification = classification
        self.score = score
        self.body_format = body_format

        if isinstance(title_text, list):
            title_text = ''.join(title_text)
        self.title_text = safe_str(title_text)

    def __call__(self):
        self._section.body = self.body

        return self._section

    def add_line(self, text: str or list):
        # add_line with a list should join without newline seperator.
        # use add_lines if list should be split one element per line.
        if isinstance(text, list):
            text = ''.join(text)
        textstr = safe_str(text)
        if len(self.body) != 0:
            textstr = '\n' + textstr
        self.body = self.body + textstr

    def add_lines(self, line_list: list):
        if not isinstance(line_list, list):
            log.warning("add_lines called with invalid type: %s. ignoring", type(line_list))
            return

        segment = '\n'.join(line_list)
        if len(self.body) == 0:
            self.body = segment
        else:
            self.body = self.body + '\n' + segment

    def get(self):
        return self._section

    def set_body(self, body: str, body_format: BODY_FORMAT = BODY_FORMAT.TEXT) -> None:
        self.body = body
        self.body_format = body_format


class Result:
    def __init__(self) -> None:
        self._result = ResultBody()
        self.sections = []
        self.tags = []

    def __call__(self) -> ResultBody:
        return self._result

    def add_section(self, section: ResultSection, on_top: bool = False) -> None:

        if on_top:
            self.sections.insert(0, section.get())
        else:
            self.sections.append(section.get())

    def add_tag(self, classification: CLASSIFICATION, value, context, type):
        # Check to see if tag already exists before adding
        for existing_tag in self.tags:
            if existing_tag.type == type and existing_tag.value == value:
                return

        tag = Tag()
        tag.classification = classification
        tag.value = value
        tag.context = context
        tag.type = type

        self.tags.append(tag)

    def report_heuristic(self):
        # Check to see if heuristic already exists before adding
        for existing_tag in self.tags:
            if existing_tag.type == type and existing_tag.value == value:
                return

        heuristic = Heuristic()
        # heuristic.classification =
        # heuristic.description =
        # heuristic.filetype =
        # heuristic.heur_id =
        # heuristic.name =

