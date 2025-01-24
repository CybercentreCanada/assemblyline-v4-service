import logging
import signal
import time
from os import environ
from subprocess import Popen, TimeoutExpired

from assemblyline.common import log as al_log
from assemblyline_v4_service.run_privileged_service import RunPrivilegedService

PRIVILEGED = environ.get('PRIVILEGED', 'false') == 'true'


def check_processes(service_process, task_handler_process, log):
    rs_rc = service_process.poll()
    th_rc = task_handler_process.poll()

    # If both processes exited, then return non-zero exit code
    if rs_rc is not None and th_rc is not None:
        log.info(f"run_service: exit({rs_rc}) | task_handler: exit({th_rc})")
        exit(th_rc or rs_rc)

    # Check and exit if task_handler process exited
    # No point continuing to run, since even if the service process finishes something,
    # since there is something wrong with the task handler, we can't upload it
    if th_rc is not None:
        log.info(f"task_handler: exit({th_rc})")
        service_process.terminate()
        exit(th_rc)

    # If the service process has crashed tell the task handler something is wrong,
    # then wait for it to exit voluntarily
    if rs_rc is not None:
        if rs_rc != 0:
            # If it's not a 0 return code, make this an error
            log.error(f"The service has crashed with exit code: {rs_rc}. The container will be stopped...")
        else:
            log.info(f"run_service: exit({rs_rc})")
        task_handler_process.send_signal(signal.SIGUSR1)
        try:
            task_handler_process.wait(timeout=60)
        except TimeoutExpired:
            pass


def run_task_handler():
    al_log.init_logging("assemblyline.service.process_handler")

    log = logging.getLogger("assemblyline.service.process_handler")

    # Start the two processes
    rs_p = Popen(['python3', '-m', 'assemblyline_v4_service.run_service'])
    th_p = Popen(['python3', '-m', 'assemblyline_service_client.task_handler'])

    def forward_signal(signal_number, _frame):
        th_p.send_signal(signal_number)

    signal.signal(signal.SIGUSR1, forward_signal)
    signal.signal(signal.SIGUSR2, forward_signal)
    signal.signal(signal.SIGTERM, forward_signal)

    while True:
        check_processes(rs_p, th_p, log)

        # Wait 2 seconds before polling process status
        time.sleep(2)


if __name__ == '__main__':
    if PRIVILEGED:
        RunPrivilegedService().serve_forever()
    else:
        run_task_handler()
