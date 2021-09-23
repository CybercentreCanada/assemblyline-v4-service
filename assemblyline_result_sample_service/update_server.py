import logging
import os
import tempfile
import time

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.odm.models.service import Service, UpdateSource

from assemblyline_client import get_client
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key
from assemblyline_v4_service.updater.helper import url_download, SkipSource

al_log.init_logging('updater.sample')
classification = forge.get_classification()


LOGGER = logging.getLogger('assemblyline.updater.sample')

UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')
UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/sample_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/sample_updater_output")
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'sample_updates')

BLOCK_SIZE = 64 * 1024
HASH_LEN = 1000


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
