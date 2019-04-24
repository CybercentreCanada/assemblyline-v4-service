from assemblyline.odm.models.result import Tag
from assemblyline.common.str_utils import StringTable, NamedConstants, safe_str


class ResultSection(dict):
    def __init__(self,
                 body='',
                 body_format="TEXT"):
        super(ResultSection, self).__init__()
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

    def set_body(self, body, body_format="TEXT"):
        self.body = body
        self.body_format = body_format


class Result(dict):
    def __init__(self,
                 sections=None,
                 tags=None):
        super(Result, self).__init__()
        self.sections = sections or []
        self.tags = tags or []

    def add_section(self, section: ResultSection, on_top: bool = False):

        if on_top:
            self.sections.insert(0, section)
        else:
            self.sections.append(section)

    def add_tag(self, type, value):

        # Check to see if tag already exists before adding
        for existing_tag in self.tags:
            if existing_tag['type'] == tag['type'] and existing_tag['value'] == tag['value']:
                return
