import logging

from alv4_service.common import helper
from alv4_service.common.request import ServiceRequest
from alv4_service.common.task import Task
from assemblyline.common import exceptions, log, version
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.models.result import ResultBody


class ServiceBase:
    def __init__(self, config: dict = None) -> None:
        # Load the service attributes from the service manifest
        self._load_service_attributes()

        # Start with default service parameters and override with anything provided
        self.config = self.service_config
        if config:
            self.config.update(config)

        # Initialize logging for the service
        log.init_logging(f'{self.service_name}', log_level=logging.INFO)
        self.log = logging.getLogger(f'assemblyline.service.{self.service_name.lower()}')

        self._task = None

        self._working_directory = None

    def _cleanup(self) -> None:
        self._task = None
        self._working_directory = None

    def _handle_execute_failure(self, exception, stack_info) -> None:
        # Clear the result, in case it caused the problem
        self._task.result = None

        # Clear the extracted and supplementary files
        self._task.clear_extracted()
        self._task.clear_supplementary()

        if isinstance(exception, exceptions.RecoverableError):
            self.log.info(f"Recoverable Service Error ({self._task.sid}/{self._task.sha256}) {exception}: {stack_info}")
            self._task.save_error(stack_info, recoverable=True)
        else:
            self.log.error(f"Nonrecoverable Service Error ({self._task.sid}/{self._task.sha256}) {exception}: {stack_info}")
            self._task.save_error(stack_info, recoverable=False)

    def _load_service_attributes(self) -> None:
        service_manifest_data = helper.get_service_manifest()
        self.service_config = service_manifest_data.get('config', {})
        self.service_name = service_manifest_data.get('name')
        self.service_version = service_manifest_data.get('version')

    def _success(self) -> None:
        self._task.success()

    def execute(self, request) -> ResultBody:
        raise NotImplementedError("execute() function not implemented")

    def get_service_version(self) -> str:
        t = (version.FRAMEWORK_VERSION,
             version.SYSTEM_VERSION,
             self.service_version)
        return '.'.join([str(v) for v in t])

    def get_tool_version(self) -> str or None:
        return None

    def handle_task(self, task: ServiceTask) -> None:
        try:
            self._task = Task(task)
            self.log.info(f"Starting task: {self._task.sid}/{self._task.sha256} ({self._task.type})")
            self._working_directory = self._task.working_directory()
            self._task.start(self.get_service_version(), self.get_tool_version())

            request = ServiceRequest(self._task)
            self.execute(request)

            result = self._task.result
            self._task.set_result(result)
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
        self.log.info(f"Starting service: {self.service_name}")
        self.start()

    def stop(self) -> None:
        """
        Called at worker stop.

        :return:
        """
        pass

    def stop_service(self) -> None:
        # Perform common stop routines and then invoke the child's stop().
        self.log.info(f"Stopping service: {self.service_name}")
        self.stop()
