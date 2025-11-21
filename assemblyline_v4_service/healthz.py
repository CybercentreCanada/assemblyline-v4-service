"""Utility script for reading pod health status for kubernetes deployments."""
from os import environ, path

import requests


UPDATES_CA = environ.get('UPDATES_CA', '/etc/assemblyline/ssl/al_root-ca.crt')
SERVICE_SERVER_CA = environ.get('SERVICE_SERVER_CA', '/etc/assemblyline/ssl/al_root-ca.crt')
REQUEST_TIMEOUT = 30


def perform_check():
    """
    Test prerequisites for this service being healthy.

    Intended for use with Kubernetes deployments.
    """

    # Probe service server
    service_api_host = environ['SERVICE_API_HOST']
    verify = None if not service_api_host.startswith('https') else SERVICE_SERVER_CA
    if not requests.get(f"{service_api_host}/healthz/live", verify=verify, timeout=REQUEST_TIMEOUT).ok:
        raise RuntimeError('Unable to reach service-server')

    # If running with an updater, check for availability. Make sure test doesn't run on the actual updater.
    if environ.get('updates_host') and not environ['HOSTNAME'].startswith(environ['updates_host']):
        scheme, verify = ("http", None) if not path.exists(UPDATES_CA) else ("https", UPDATES_CA)
        updater_url = f"{scheme}://{environ['updates_host']}:{environ['updates_port']}/healthz/live"
        if not requests.get(updater_url, verify=verify, timeout=REQUEST_TIMEOUT).ok:
            raise RuntimeError('Unable to reach local update server')


if __name__ == '__main__':
    perform_check()
