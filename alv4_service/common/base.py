import logging
import os
import shutil

import yaml

from alv4_service.common.request import ServiceRequest
from alv4_service.common.task import Task
from assemblyline.common import exceptions
from assemblyline.common import log
from assemblyline.common.dict_utils import recursive_update
from assemblyline.odm.models.service import Service


class ServiceBase:
    def __init__(self, config=None):
        # Get the default service attributes
        self.attributes = self._get_default_service_attributes()

        # Start with default service parameters and override with anything provided
        self.config = self.attributes.config
        if config:
            self.config.update(config)

        # Initialize logging for the service
        log.init_logging(f'{self.attributes.name}', log_level=logging.INFO)

        # Initialize non-trivial members in start_service rather than __init__
        self.log = logging.getLogger(f'assemblyline.service.{self.attributes.name.lower()}')

        self.task = None

        self._working_directory = None


    def _cleanup_working_directory(self):
        try:
            if self._working_directory:
                shutil.rmtree(self._working_directory)
        except Exception:
            self.log.warning(f"Could not remove working directory: {self._working_directory}")
        self._working_directory = None

    @staticmethod
    def _get_default_service_attributes(yml_config=None):
        if yml_config is None:
            yml_config = os.path.join(os.path.dirname(__file__), 'service_config.yml')

        # Initialize a default service
        service = Service().as_primitives()

        # Load modifiers from the yaml config
        if os.path.exists(yml_config):
            with open(yml_config) as yml_fh:
                yml_data = yaml.safe_load(yml_fh.read())
                if yml_data:
                    service = recursive_update(service, yml_data)

        return Service(service)

    def _handle_execute_failure(self, task: Task, exception, stack_info):
        # Clear the result, in case it caused the problem
        task.result = None

        # Clear the extracted and supplementary files
        task.clear_extracted()
        task.clear_supplementary()

        if isinstance(exception, exceptions.RecoverableError):
            self.log.info(f"Recoverable Service Error ({task.sid}/{task.sha256}) {exception}: {stack_info}")
            task.save_error(stack_info, recoverable=True)
        else:
            self.log.error(f"Nonrecoverable Service Error ({task.sid}/{task.sha256}) {exception}: {stack_info}")
            task.save_error(stack_info, recoverable=False)

    def _success(self, task: Task):
        task.success()

    def execute(self, request: ServiceRequest) -> None:
        raise NotImplementedError("execute() function not implemented")

    def get_tool_version(self):
        return ''

    def handle_task(self, task: Task):
        self.log.info(f"Starting task: {task.sid}/{task.sha256} ({task.type})")

        try:
            self.task = task
            self._working_directory = task.working_directory()
            task.start(self.attributes.version, self.get_tool_version())
            request = ServiceRequest(self, task)
            result = self.execute(request)
            task.set_result(result)
            self._success(task)
        except Exception as ex:
            self._handle_execute_failure()
        finally:
            self._cleanup_working_directory()
            self.task = None

    def start(self):
        """
        Called at worker start.

        :return:
        """
        pass

    def start_service(self):
        self.log.info(f"Starting service: {self.attributes.name}")
        self.start()

    def stop(self):
        """
        Called at worker stop.

        :return:
        """
        pass

    def stop_service(self):
        # Perform common stop routines and then invoke the child's stop().
        self.log.info(f"Stopping service: {self.attributes.name}")
        self.stop()
