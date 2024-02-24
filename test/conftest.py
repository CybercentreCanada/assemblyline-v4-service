"""
Pytest configuration file, setup global pytest fixtures and functions here.
"""
import os
import pytest

from assemblyline.common import forge
from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.datastore.store import ESStore

original_skip = pytest.skip

# Check if we are in an unattended build environment where skips won't be noticed
IN_CI_ENVIRONMENT = any(indicator in os.environ for indicator in
                        ['CI', 'BITBUCKET_BUILD_NUMBER', 'AGENT_JOBSTATUS'])


def skip_or_fail(message):
    """Skip or fail the current test, based on the environment"""
    if IN_CI_ENVIRONMENT:
        pytest.fail(message)
    else:
        original_skip(message)


# Replace the built in skip function with our own
pytest.skip = skip_or_fail


@pytest.fixture(scope='session')
def config():
    config = forge.get_config()
    config.logging.log_level = 'INFO'
    config.logging.log_as_json = False
    config.core.metrics.apm_server.server_url = None
    config.core.metrics.export_interval = 1
    config.datastore.archive.enabled = True
    return config


@pytest.fixture(scope='module')
def datastore_connection(config):
    store = ESStore(config.datastore.hosts)
    ret_val = store.ping()
    if not ret_val:
        pytest.skip("Could not connect to datastore")
    return AssemblylineDatastore(store)


@pytest.fixture(scope='module')
def clean_datastore(datastore_connection: AssemblylineDatastore):
    for name in datastore_connection.ds.get_models():
        datastore_connection.get_collection(name).wipe()
    return datastore_connection


@pytest.fixture(scope='function')
def function_clean_datastore(datastore_connection: AssemblylineDatastore):
    for name in datastore_connection.ds.get_models():
        datastore_connection.get_collection(name).wipe()
    return datastore_connection
