import logging
import signal
import time

from subprocess import Popen

from assemblyline.common import log as al_log


def check_processes(service_process, task_handler_process):
    rs_rc = service_process.poll()
    th_rc = task_handler_process.poll()

    # If both processes exited, then return the highest exit code
    if rs_rc is not None and th_rc is not None:
        log.info(f"run_service: exit({rs_rc}) | task_handler: exit({th_rc})")
        exit(max(rs_rc, th_rc))

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
        log.info(f"run_service: exit({rs_rc})")
        task_handler_process.send_signal(signal.SIGUSR1)


if __name__ == '__main__':
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
        check_processes(rs_p, th_p)

        # Wait 2 seconds before polling process status
        time.sleep(2)
