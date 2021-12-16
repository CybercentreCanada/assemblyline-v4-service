import os
import time
import requests
from assemblyline_core.tasking_client import TaskingClient

DEFAULT_SERVICE_SERVER = "http://localhost:5003"
DEFAULT_AUTH_KEY = "ThisIsARandomAuthKey...ChangeMe!"
PRIVILEGED = os.environ.get('PRIVILEGED', 'false') == 'true'


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
        self.tasking_client = TaskingClient() if PRIVILEGED else None

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
        tag_types = None
        if tag_list:
            if not isinstance(tag_list, list):
                raise ValueError("Parameter tag_list should be a list of strings.")
            tag_types = ','.join(tag_list)
            url = f"{self.service_api_host}/api/v1/safelist/?tag_types={tag_types}"
        else:
            url = f"{self.service_api_host}/api/v1/safelist/"

        return self.tasking_client.get_safelist_for_tags(tag_types=tag_types) \
            if PRIVILEGED else self._with_retries(self.session.get, url)

    def lookup_safelist(self, qhash):
        try:
            return self.tasking_client.exists(qhash=qhash) if PRIVILEGED \
                else self._with_retries(self.session.get, f"{self.service_api_host}/api/v1/safelist/{qhash}/")
        except ServiceAPIError as e:
            if e.status_code == 404:
                return None
            else:
                raise
