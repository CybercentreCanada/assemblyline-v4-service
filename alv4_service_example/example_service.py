import time

from alv4_service.common.base import ServiceBase
from alv4_service.common.result import Result, ResultSection, SCORE


class ExampleService(ServiceBase):
    def __init__(self):
        super(ExampleService, self).__init__()

    def start(self):
        self.log.info(f"start() from {self.attributes.name} service called")

    def execute(self, request):
        time.sleep(5)
        result = Result()
        section = ResultSection(SCORE.NULL, "Example service completed")
        section.add_line("Nothing done.")
        result.add_section(section)
        request.result = result
