import os
import requests
import time
import traceback

from assemblyline_core.safelist_client import SafelistClient
from io import StringIO
DEFAULT_SERVICE_SERVER = "http://localhost:5003"
DEFAULT_AUTH_KEY = "ThisIsARandomAuthKey...ChangeMe!"
DEVELOPMENT_MODE = False

with StringIO() as stack_trace:
    # Check if run_service_once or pytest is in the stack trace to determine if we're running the service in a development mode
    traceback.print_stack(file=stack_trace)
    stack_trace.seek(0)
    read_stack_trace = stack_trace.read()

    if 'run_service_once' in read_stack_trace or 'pytest' in read_stack_trace:
        DEVELOPMENT_MODE = True


class ServiceAPIError(Exception):
    def __init__(self, message, status_code, api_response=None, api_version=None):
        super(ServiceAPIError, self).__init__(message)
        self.api_response = api_response
        self.api_version = api_version
        self.status_code = status_code


class ServiceAPI:
    def __init__(self, service_attributes, logger):
        self.log = logger
        self.service_api_host = os.environ.get("SERVICE_API_HOST", DEFAULT_SERVICE_SERVER)
        self.session = requests.Session()
        self.session.headers.update(dict(
            X_APIKEY=os.environ.get("SERVICE_API_KEY", DEFAULT_AUTH_KEY),
            container_id=os.environ.get('HOSTNAME', 'dev-service'),
            service_name=service_attributes.name,
            service_version=service_attributes.version
        ))
        if self.service_api_host.startswith('https'):
            self.session.verify = os.environ.get('SERVICE_SERVER_ROOT_CA_PATH', '/etc/assemblyline/ssl/al_root-ca.crt')

    def _with_retries(self, func, url):
        retries = 0
        while True:
            try:
                resp = func(url)
                if resp.ok:
                    return resp.json()['api_response']
                else:
                    try:
                        resp_data = resp.json()
                        raise ServiceAPIError(resp_data["api_error_message"], resp.status_code,
                                              api_version=resp_data["api_server_version"],
                                              api_response=resp_data["api_response"])
                    except Exception as e:
                        if isinstance(e, ServiceAPIError):
                            raise

                        raise ServiceAPIError(resp.content, resp.status_code)
            except (requests.ConnectionError, requests.Timeout):
                if not retries:
                    self.log.info("Service server is unreachable, retrying now ...")
                elif retries % 10 == 0:
                    self.log.warning(f"Service server has been unreachable for the past {retries} attempts. "
                                     "Is there something wrong with it?")
                retries += 1
                time.sleep(min(2, 2 ** (retries - 7)))

    def get_safelist(self, tag_list=None):
        if DEVELOPMENT_MODE:
            return {}

        if tag_list:
            if not isinstance(tag_list, list):
                raise ValueError("Parameter tag_list should be a list of strings.")
            url = f"{self.service_api_host}/api/v1/safelist/?tag_types={','.join(tag_list)}"
        else:
            url = f"{self.service_api_host}/api/v1/safelist/"

        return self._with_retries(self.session.get, url)

    def lookup_safelist(self, qhash):
        if DEVELOPMENT_MODE:
            return None
        try:
            return self._with_retries(self.session.get, f"{self.service_api_host}/api/v1/safelist/{qhash}/")
        except ServiceAPIError as e:
            if e.status_code == 404:
                return None
            else:
                raise


class PrivilegedServiceAPI:
    def __init__(self, logger):
        self.log = logger
        self.safelist_client = SafelistClient()

    def get_safelist(self, tag_list=None):
        if DEVELOPMENT_MODE:
            return {}
        tag_types = None

        if tag_list and not isinstance(tag_list, list):
            raise ValueError("Parameter tag_list should be a list of strings.")

        return self.safelist_client.get_safelisted_tags(tag_types)

    def lookup_safelist(self, qhash):
        if DEVELOPMENT_MODE:
            return None
        return self.safelist_client.exists(qhash)
