import logging
import os
import tempfile
import time

import certifi
import requests
from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.common.isotime import iso_to_epoch
from assemblyline.odm.models.service import Service, UpdateSource

from assemblyline_client import get_client
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key

al_log.init_logging('updater.sample')
classification = forge.get_classification()


LOGGER = logging.getLogger('assemblyline.updater.sample')

UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')
UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/sample_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/sample_updater_output")
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'sample_updates')

BLOCK_SIZE = 64 * 1024
HASH_LEN = 1000


class SkipSource(RuntimeError):
    pass


def add_cacert(cert: str):
    # Add certificate to requests
    cafile = certifi.where()
    with open(cafile, 'a') as ca_editor:
        ca_editor.write(f"\n{cert}")


def url_download(source, target_path, logger, previous_update=None):
    uri = source['uri']
    username = source.get('username', None)
    password = source.get('password', None)
    ca_cert = source.get('ca_cert', None)
    ignore_ssl_errors = source.get('ssl_ignore_errors', False)
    auth = (username, password) if username and password else None

    proxy = source.get('proxy', None)
    headers = source.get('headers', None)

    logger.info(f"This source is configured to {'ignore SSL errors' if ignore_ssl_errors else 'verify SSL'}.")
    if ca_cert:
        logger.info("A CA certificate has been provided with this source.")
        add_cacert(ca_cert)

    # Create a requests session
    session = requests.Session()
    session.verify = not ignore_ssl_errors

    # Let https requests go through proxy
    if proxy:
        os.environ['https_proxy'] = proxy

    try:
        if isinstance(previous_update, str):
            previous_update = iso_to_epoch(previous_update)

        # Check the response header for the last modified date
        response = session.head(uri, auth=auth, headers=headers)
        last_modified = response.headers.get('Last-Modified', None)
        if last_modified:
            # Convert the last modified time to epoch
            last_modified = time.mktime(time.strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z"))

            # Compare the last modified time with the last updated time
            if previous_update and last_modified <= previous_update:
                # File has not been modified since last update, do nothing
                logger.info("The file has not been modified since last run, skipping...")
                return False

        if previous_update:
            previous_update = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(previous_update))
            if headers:
                headers['If-Modified-Since'] = previous_update
            else:
                headers = {'If-Modified-Since': previous_update}

        logger.info(f"Downloading file from: {source['uri']}")
        with session.get(uri, auth=auth, headers=headers, stream=True) as response:
            # Check the response code
            if response.status_code == requests.codes['not_modified']:
                # File has not been modified since last update, do nothing
                logger.info("The file has not been modified since last run, skipping...")
                raise SkipSource
            elif response.ok:
                with open(target_path, 'wb') as f:
                    for content in response.iter_content(BLOCK_SIZE):
                        f.write(content)

                # Clear proxy setting
                if proxy:
                    del os.environ['https_proxy']

                # Return file_path
                return True
    except requests.Timeout:
        pass
    except Exception as e:
        # Catch all other types of exceptions such as ConnectionError, ProxyError, etc.
        logger.warning(str(e))
        return False
    finally:
        # Close the requests session
        session.close()


class SampleUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.updater_type = "sample"

    def do_source_update(self, service: Service) -> None:
        self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}...")
        run_time = time.time()
        username = self.ensure_service_account()
        with temporary_api_key(self.datastore, username) as api_key:
            client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)
            old_update_time = self.get_source_update_time()

            self.log.info("Connected!")

            # Parse updater configuration
            previous_hashes: dict[str, str] = self.get_source_extra()
            sources: dict[str, UpdateSource] = {_s['name']: _s for _s in service.update_config.sources}
            files_sha256: dict[str, str] = {}
            source_default_classification = {}

            # Go through each source and download file
            for source_name, source_obj in sources.items():
                source = source_obj.as_primitives()
                uri: str = source['uri']
                cache_name = f"{source_name}.zip"
                source_default_classification[source_name] = source.get('default_classification',
                                                                        classification.UNRESTRICTED)
                self.log.info(f"Processing source: {source['name'].upper()}")
                extracted_path = os.path.join(UPDATE_DIR, source['name'])

                try:
                    url_download(uri, extracted_path, self.log, previous_update=old_update_time)
                except SkipSource:
                    if cache_name in previous_hashes:
                        files_sha256[cache_name] = previous_hashes[cache_name]
                    continue

                # On source update, parse into a JSON structure and import into Assemblyline using client
                # Section of code taken from cccs/assemblyline-service-safelist
                #
                # if os.path.exists(extracted_path) and os.path.isfile(extracted_path):
                #     success = 0
                #     with open(extracted_path) as fh:
                #         reader = csv.reader(fh, delimiter=',', quotechar='"')
                #         hash_list = []
                #         for line in reader:
                #             sha1, md5, _, filename, size = line[:5]
                #             if sha1 == "SHA-1":
                #                 continue

                #             data = {
                #                 "file": {"name": [filename], "size": size},
                #                 "hashes": {"md5": md5.lower(), "sha1": sha1.lower()},
                #                 "sources": [
                #                     {"name": source['name'],
                #                      'type': 'external',
                #                      "reason": [f"Exist in source as {filename}"]}
                #                 ],
                #                 'type': "file"
                #             }
                #             hash_list.append(data)

                #             if len(hash_list) % HASH_LEN == 0:
                #                 try:
                #                     resp = client._connection.put("api/v4/sample/add_update_many/", json=hash_list)
                #                     success += resp['success']
                #                 except Exception as e:
                #                     self.log.error(f"Failed to insert hash into sample: {str(e)}")

                #                 hash_list = []

                #     os.unlink(extracted_path)
                #     self.log.info(f"Import finished. {success} hashes have been processed.")

        self.set_source_update_time(run_time)
        self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == '__main__':
    with SampleUpdateServer() as server:
        server.serve_forever()
