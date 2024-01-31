import os
import time

import requests
from assemblyline_core.badlist_client import BadlistClient
from assemblyline_core.safelist_client import SafelistClient
from assemblyline_v4_service.common.utils import DEVELOPMENT_MODE
from assemblyline_v4_service.common.helper import get_service_manifest

DEFAULT_SERVICE_SERVER = "http://localhost:5003"
DEFAULT_AUTH_KEY = "ThisIsARandomAuthKey...ChangeMe!"


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
        self.session.headers.update({
            "X-APIKey": os.environ.get("SERVICE_API_KEY", DEFAULT_AUTH_KEY),
            "Container-ID": os.environ.get('HOSTNAME', 'dev-service'),
            "Service-Name": service_attributes.name,
            "Service-Version": service_attributes.version,
            "Service-Tool-Version": get_service_manifest().get('tool_version', '')
        })
        if self.service_api_host.startswith('https'):
            self.session.verify = os.environ.get('SERVICE_SERVER_ROOT_CA_PATH', '/etc/assemblyline/ssl/al_root-ca.crt')

    def _with_retries(self, func, url, **kwargs):
        retries = 0
        while True:
            try:
                resp = func(url, **kwargs)
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

    def lookup_badlist_tags(self, tag_map: dict):
        if DEVELOPMENT_MODE or not tag_map:
            return []

        if not isinstance(tag_map, dict) and not all([isinstance(x, list) for x in tag_map.values()]):
            raise ValueError("Parameter tag_list should be a dictionary tag_type mapping to a list of tag_values.")
        url = f"{self.service_api_host}/api/v1/badlist/tags/"

        return self._with_retries(self.session.post, url, json=tag_map)

    def lookup_badlist(self, qhash):
        if DEVELOPMENT_MODE or qhash is None:
            return None
        try:
            return self._with_retries(self.session.get, f"{self.service_api_host}/api/v1/badlist/{qhash}/")
        except ServiceAPIError as e:
            if e.status_code == 404:
                return None
            else:
                raise

    def lookup_badlist_ssdeep(self, ssdeep):
        if DEVELOPMENT_MODE or ssdeep is None:
            return []
        try:
            data = {"ssdeep": ssdeep}
            return self._with_retries(self.session.post, f"{self.service_api_host}/api/v1/badlist/ssdeep/", json=data)
        except ServiceAPIError as e:
            if e.status_code == 404:
                return []
            else:
                raise

    def lookup_badlist_tlsh(self, tlsh):
        if DEVELOPMENT_MODE or tlsh is None:
            return []
        try:
            data = {"tlsh": tlsh}
            return self._with_retries(self.session.post, f"{self.service_api_host}/api/v1/badlist/tlsh/", json=data)
        except ServiceAPIError as e:
            if e.status_code == 404:
                return []
            else:
                raise

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
        self.badlist_client = BadlistClient()
        self.safelist_client = SafelistClient()

    def lookup_badlist_tags(self, tag_map):
        if DEVELOPMENT_MODE or not tag_map:
            return []

        if not isinstance(tag_map, dict) and not all([isinstance(x, list) for x in tag_map.values()]):
            raise ValueError("Parameter tag_list should be a dictionary tag_type mapping to a list of tag_values.")

        return self.badlist_client.exists_tags(tag_map)

    def lookup_badlist(self, qhash):
        if DEVELOPMENT_MODE or qhash is None:
            return None
        return self.badlist_client.exists(qhash)

    def lookup_badlist_ssdeep(self, ssdeep):
        if DEVELOPMENT_MODE or ssdeep is None:
            return []
        return self.badlist_client.find_similar_ssdeep(ssdeep)

    def lookup_badlist_tlsh(self, tlsh):
        if DEVELOPMENT_MODE or tlsh is None:
            return []
        return self.badlist_client.find_similar_tlsh(tlsh)

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
