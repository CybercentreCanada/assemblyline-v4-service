from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.result import ResultBody, Section, Tag


class ResultSection:
    def __init__(self,
                 body='',
                 body_format="TEXT"):
        self._section = Section()
        self.body = body
        self.body_format = body_format

    def add_line(self, text):
        # add_line with a list should join without newline seperator.
        # use add_lines if list should be split one element per line.
        if isinstance(text, list):
            text = ''.join(text)
        textstr = safe_str(text)
        if len(self.body) != 0:
            textstr = '\n' + textstr
        self.body = self.body + textstr

    def add_lines(self, line_list):
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

    def set_body(self, body, body_format="TEXT"):
        self.body = body
        self.body_format = body_format


class Result:
    def __init__(self):
        self._result = ResultBody()
        self.sections = []
        self.tags = []

    def add_section(self, section: ResultSection, on_top: bool = False):

        if on_top:
            self.sections.insert(0, section.get())
        else:
            self.sections.append(section.get())

    def add_tag(self, classification, value, context, type):
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

