from alv4_service.common.base import ServiceBase
from alv4_service.common.result import Result, ResultSection


class ExampleService(ServiceBase):
    def __init__(self):
        super(ExampleService, self).__init__()

    def start(self):
        self.log.info(f"{self.service.name} service started")

    def execute(self, request):
        result = Result()
        section = ResultSection(SCORE.NULL, "Tutorial service completed")
        section.add_line("Nothing done.")
        result.add_section(section)
        request.result = result