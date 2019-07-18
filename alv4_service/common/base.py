import logging
import os

import yaml

from alv4_service.common.request import ServiceRequest
from alv4_service.common.task import Task
from assemblyline.common import exceptions, log, version
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.result import ResultBody
from assemblyline.odm.models.service import Service


class ServiceBase:
    def __init__(self, config: dict = None) -> None:
        # Get the default service attributes
        self.attributes = self._get_default_service_attributes()

        # Start with default service parameters and override with anything provided
        self.config = self.attributes.config
        if config:
            self.config.update(config)

        # Initialize logging for the service
        log.init_logging(f'{self.attributes.name}', log_level=logging.INFO)
        self.log = logging.getLogger(f'assemblyline.service.{self.attributes.name.lower()}')

        self.task = None

        self._working_directory = None

    def _cleanup(self) -> None:
        self.task = None
        self._working_directory = None

    @staticmethod
    def _get_default_service_attributes(yml_config: str = None) -> Service:
        if yml_config is None:
            yml_config = os.path.join(os.getcwd(), 'service_manifest.yml')

        # Load modifiers from the yaml config
        if os.path.exists(yml_config):
            with open(yml_config) as yml_fh:
                yml_data = yaml.safe_load(yml_fh.read())
                if yml_data:
                    yml_data.pop('file_required', None)
                    service = Service(yml_data)

        return service

    def _handle_execute_failure(self, exception, stack_info) -> None:
        # Clear the result, in case it caused the problem
        self.task.result = None

        # Clear the extracted and supplementary files
        self.task.clear_extracted()
        self.task.clear_supplementary()

        if isinstance(exception, exceptions.RecoverableError):
            self.log.info(f"Recoverable Service Error ({self.task.sid}/{self.task.sha256}) {exception}: {stack_info}")
            self.task.save_error(stack_info, recoverable=True)
        else:
            self.log.error(f"Nonrecoverable Service Error ({self.task.sid}/{self.task.sha256}) {exception}: {stack_info}")
            self.task.save_error(stack_info, recoverable=False)

    def _success(self) -> None:
        self.task.success()

    def execute(self, request) -> ResultBody:
        raise NotImplementedError("execute() function not implemented")

    def get_service_version(self) -> str:
        t = (version.FRAMEWORK_VERSION,
             version.SYSTEM_VERSION,
             self.attributes.version)
        return '.'.join([str(v) for v in t])

    def get_tool_version(self) -> str or None:
        return None

    def handle_task(self, task: ServiceTask) -> None:
        try:
            self.task = Task(task)
            self.log.info(f"Starting task: {self.task.sid}/{self.task.sha256} ({self.task.type})")
            self._working_directory = self.task.working_directory()
            self.task.start(self.attributes.version, self.get_tool_version())
            request = ServiceRequest(self.task)
            self.execute(request)

            result = self.task.result
            self.task.set_result(result)
            self._success()
        except Exception as ex:
            self._handle_execute_failure(ex, exceptions.get_stacktrace_info(ex))
        finally:
            self._cleanup()

    def start(self) -> None:
        """
        Called at worker start.

        :return:
        """
        pass

    def start_service(self) -> None:
        self.log.info(f"Starting service: {self.attributes.name}")
        self.start()

    def stop(self) -> None:
        """
        Called at worker stop.

        :return:
        """
        pass

    def stop_service(self) -> None:
        # Perform common stop routines and then invoke the child's stop().
        self.log.info(f"Stopping service: {self.attributes.name}")
        self.stop()
