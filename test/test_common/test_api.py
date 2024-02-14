import logging
from collections import OrderedDict
from multiprocessing import Process

import pytest
import requests_mock
from assemblyline.common.version import FRAMEWORK_VERSION, SYSTEM_VERSION
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.api import *
from requests import ConnectionError, Session, Timeout


def test_development_mode():
    assert DEVELOPMENT_MODE is True


def test_serviceapierror_init():
    # Init with None
    sae = ServiceAPIError(None, None)
    assert sae.api_response is None
    assert sae.api_version is None
    assert sae.status_code is None

    # Init with values
    sae = ServiceAPIError("message", 200, {"blah": "blah"}, "v4")
    assert sae.api_response == {"blah": "blah"}
    assert sae.api_version == "v4"
    assert sae.status_code == 200


def test_serviceapi_init():
    service_attributes = helper.get_service_attributes()
    sa = ServiceAPI(service_attributes, None)
    assert sa.log is None
    assert isinstance(sa.session, Session)
    # This value could change with different versions of Python requests
    assert sa.session.headers.pop("user-agent")
    # This changes relative to the data model
    assert sa.session.headers.pop("accept-encoding")
    # This changes when run from a container
    assert sa.session.headers.pop("container-id")
    assert sa.session.headers.__dict__ == {
        '_store': OrderedDict(
            [
                # ('user-agent', ('User-Agent', 'python-requests/2.31.0')),
                # ('accept-encoding', ('Accept-Encoding', 'gzip, deflate')),
                ('accept', ('Accept', '*/*')),
                ('connection', ('Connection', 'keep-alive')),
                ('x-apikey', ('X-APIKey', DEFAULT_AUTH_KEY)),
                # ('Container-ID', ('Container-ID', 'dev-service')),
                ('service-name', ('Service-Name', 'Sample')),
                ('service-version', ('Service-Version', f'{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.0.dev0')),
                ('service-tool-version', ('Service-Tool-Version', ''))
            ]
        )
    }


def test_serviceapi_with_retries():
    service_attributes = helper.get_service_attributes()
    log = logging.getLogger('assemblyline')
    sa = ServiceAPI(service_attributes, log)
    with requests_mock.Mocker() as m:
        url = f"{sa.service_api_host}/api/v1/blah/"

        # ConnectionError
        m.get(url, exc=ConnectionError)
        p1 = Process(target=sa._with_retries, args=(sa.session.get, url),
                     name="_with_retries with exception ConnectionError")
        p1.start()
        p1.join(timeout=2)
        p1.terminate()
        assert p1.exitcode is None

        # Timeout
        m.get(url, exc=Timeout)
        p1 = Process(target=sa._with_retries, args=(sa.session.get, url),
                     name="_with_retries with exception ConnectionError")
        p1.start()
        p1.join(timeout=2)
        p1.terminate()
        assert p1.exitcode is None

        # Status code of 200
        m.get(url, status_code=200, json={"api_response": "blah"})
        assert sa._with_retries(sa.session.get, url) == "blah"

        # Status code of 400 and no "api_error_message" key
        m.get(url, status_code=400, json={})
        with pytest.raises(ServiceAPIError):
            sa._with_retries(sa.session.get, url)

        # Status code of 400 and the required keys
        m.get(url, status_code=400, json={"api_error_message": "blah",
              "api_server_version": "blah", "api_response": "blah"})
        with pytest.raises(ServiceAPIError):
            sa._with_retries(sa.session.get, url)


def test_serviceapi_get_safelist():
    service_attributes = helper.get_service_attributes()
    log = logging.getLogger('assemblyline')
    sa = ServiceAPI(service_attributes, log)
    assert sa.get_safelist() == {}

    # TODO
    # Test not in development mode


def test_serviceapi_lookup_safelist():
    service_attributes = helper.get_service_attributes()
    log = logging.getLogger('assemblyline')
    sa = ServiceAPI(service_attributes, log)
    assert sa.lookup_safelist("qhash") is None

    # TODO
    # Test not in development mode

# TODO
# SafelistClient requires forge access

# def test_privilegedserviceapi_init():
#     log = logging.getLogger('assemblyline')
#     psa = PrivilegedServiceAPI(log)
#     assert psa.log == log
#     assert isinstance(psa.safelist_client, SafelistClient)


# def test_privilegedserviceapi_get_safelist():
#     log = logging.getLogger('assemblyline')
#     psa = PrivilegedServiceAPI(log)
#     assert psa.get_safelist() == {}

#     # TODO
#     # Test not in development mode


# def test_privilegedserviceapi_lookup_safelist():
#     log = logging.getLogger('assemblyline')
#     psa = PrivilegedServiceAPI(log)
#     assert psa.lookup_safelist("qhash") is None

    # TODO
    # Test not in development mode
