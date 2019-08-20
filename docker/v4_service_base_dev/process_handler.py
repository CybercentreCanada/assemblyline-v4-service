import time
from subprocess import Popen

if __name__ == '__main__':
    # Start the two processes
    rs_p = Popen(['python3', '/opt/alv4/alv4_service/assemblyline_v4_service/run_service.py'])
    th_p = Popen(['python3', '/opt/alv4/alv4_service_client/assemblyline_service_client/task_handler.py'])

    while True:
        rs_rc = rs_p.poll()
        th_rc = th_p.poll()

        # If both processes exited, then return the highest exit code
        if rs_rc is not None and th_rc is not None:
            print(f"run_service: exit({rs_rc}) | task_handler: exit({th_rc})")
            exit(max(rs_rc, th_rc))

        # Check and exit if run_service process exited
        if rs_rc is not None:
            print(f"run_service: exit({rs_rc})")
            exit(rs_rc)

        # Check and exit if task_handler process exited
        if th_rc is not None:
            print(f"task_handler: exit({th_rc})")
            exit(th_rc)

        # Wait 10 seconds before polling process status
        time.sleep(10)
