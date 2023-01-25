import requests

from os import environ
from assemblyline.common import forge
from sys import exit


# Intended for use with Kubernetes deployments
def perform_check():
    # If the service is privileged, test connectivity to core
    if environ.get('PRIVILEGED', 'false').lower() == 'true':
        forge.get_datastore()
        forge.get_filestore(connection_attempts=1)
        forge.get_service_queue(service=environ['AL_SERVICE_NAME'])
    else:
        service_api_host = environ['SERVICE_API_HOST']
        verify = None if not service_api_host.startswith('https') else \
            environ.get('SERVICE_SERVER_ROOT_CA_PATH', '/etc/assemblyline/ssl/al_root-ca.crt')
        # Otherwise, perform a test for service-server availability
        if not requests.get(f"{service_api_host}/healthz/live", verify=verify).ok:
            raise Exception('Unable to reach service-server')
    # If running with an updater, check for availability. Make sure test doesn't run on the actual updater.
    if environ.get('updates_host') and not environ['HOSTNAME'].startswith(environ['updates_host']):
        if not requests.get(
                f"http://{environ['updates_host']}:{environ['updates_port']}/healthz/live", verify=verify).ok:
            raise Exception('Unable to reach local update server')
    exit()


if __name__ == '__main__':
    perform_check()