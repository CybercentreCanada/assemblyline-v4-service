import time
import signal
from subprocess import Popen


def check_processes(service_process, task_handler_process):
    rs_rc = service_process.poll()
    th_rc = task_handler_process.poll()

    # If both processes exited, then return the highest exit code
    if rs_rc is not None and th_rc is not None:
        print(f"run_service: exit({rs_rc}) | task_handler: exit({th_rc})")
        exit(max(rs_rc, th_rc))

    # Check and exit if task_handler process exited
    # No point continuing to run, since even if the service process finishes something,
    # since there is something wrong with the task handler, we can't upload it
    if th_rc is not None:
        print(f"task_handler: exit({th_rc})")
        service_process.terminate()
        exit(th_rc)

    # If the service process has crashed tell the task handler something is wrong,
    # then wait for it to exit voluntarily
    if rs_rc is not None:
        print(f"run_service: exit({rs_rc})")
        task_handler_process.send_signal(signal.SIGUSR1)


if __name__ == '__main__':
    # Start the two processes
    rs_p = Popen(['python3', '/opt/alv4/alv4_service/assemblyline_v4_service/run_service.py'])
    th_p = Popen(['python3', '/opt/alv4/alv4_service_client/assemblyline_service_client/task_handler.py'])

    while True:
        check_processes(rs_p, th_p)

        # Wait 10 seconds before polling process status
        time.sleep(10)
