import importlib
import inspect
import json
import os
import tempfile
import threading

from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.models.service import SIGNATURE_DELIMITERS
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.updater.client import (
    BadlistClient,
    SafelistClient,
    SignatureClient,
    UpdaterClient,
)
from assemblyline_v4_service.updater.updater import (
    SIGNATURES_META_FILENAME,
    SOURCE_STATUS_KEY,
    ServiceUpdater,
    UniqueQueue,
)


class TestSignatureClient(SignatureClient):
    def __init__(self, output_directory: str):
        self.sync = False
        self.output_directory = output_directory

    def add_update_many(self, source, sig_type, data, dedup_name=True):
        os.makedirs(os.path.join(self.output_directory, sig_type, source), exist_ok=True)
        for d in data:
            with open(os.path.join(self.output_directory, sig_type, source, d['name']), 'w') as f:
                json.dump(d, f)

        return {'success': len(data)}

class TestBadlistClient(BadlistClient):
    def __init__(self, output_directory: str):
        self.sync = False
        self.output_directory = output_directory

    def add_update_many(self, list_of_badlist_objects):
        return {'success': len(list_of_badlist_objects)}

class TestSafelistClient(SafelistClient):
    def __init__(self, output_directory: str):
        self.sync = False
        self.output_directory = output_directory

    def add_update_many(self, list_of_safelist_objects):
        return {'success': len(list_of_safelist_objects)}

class TestUpdaterClient(UpdaterClient):
    def __init__(self, output_directory: str):
        self._sync = False
        self._classification_override = False
        self.signature = TestSignatureClient(output_directory)
        self.badlist = TestBadlistClient(output_directory)
        self.safelist = TestSafelistClient(output_directory)

def load_rules(service: ServiceBase):
    with tempfile.TemporaryDirectory() as latest_updates_dir:
        updater_module = importlib.import_module(service.service_attributes.dependencies['updates'].container.command[-1])
        # Find the UpdaterServer class
        for v in updater_module.__dict__.values():
            if inspect.isclass(v) and issubclass(v, ServiceUpdater) and v != ServiceUpdater:
                updater_class = v
                break


        # Implement a class to be used with RunServiceOnce without a dependency on Assemblyline
        class TestServiceUpdater(updater_class):
            def __init__(self, *args, **kwargs):
                self.update_data_hash = {}
                self._current_source = ""
                self.log = service.log
                self._service = service.service_attributes
                self.update_queue = UniqueQueue()
                self.updater_type = self._service.name.lower()
                self.delimiter = self._service.update_config.signature_delimiter
                self.default_pattern = self._service.update_config.default_pattern
                self.signatures_meta = {}
                [self.update_queue.put(update.name) for update in self._service.update_config.sources]

                self.latest_updates_dir = latest_updates_dir
                self.client = TestUpdaterClient(latest_updates_dir)
                self.source_update_flag = threading.Event()
                self.local_update_flag = threading.Event()
                self.local_update_start = threading.Event()

            def set_source_update_time(self, update_time: float): ...

            def set_source_extra(self, extra_data): ...

            def set_active_config_hash(self, config_hash: int): ...

            # Keep a record of the source status as a dictionary
            def push_status(self, state: str, message: str):
                # Push current state of updater with source
                self.log.debug(f"Pushing state for {self._current_source}: [{state}] {message}")
                self.update_data_hash[f'{self._current_source}.{SOURCE_STATUS_KEY}'] = \
                    dict(state=state, message=message, ts=now_as_iso())

            def do_source_update(self):
                super().do_source_update(self._service)

            def do_local_update(self):
                if self._service.update_config.generates_signatures:
                    signaure_data = []
                    updatepath = os.path.join(self.latest_updates_dir, self.updater_type)
                    for source in os.listdir(updatepath):
                        sourcepath = os.path.join(updatepath, source)

                        for file in os.listdir(sourcepath):
                            # Save signatures to disk
                            filepath = os.path.join(sourcepath, file)
                            with open(filepath) as f:
                                data = json.load(f)

                                signaure_data.append(data.pop('data'))
                                self.signatures_meta[data['signature_id']] = data

                            if self.delimiter != "file":
                                os.remove(filepath)

                        if self.delimiter != "file":
                            # Render the response when calling `client.signature.download`
                            os.removedirs(sourcepath)
                            with open(os.path.join(self.latest_updates_dir, source), 'w') as f:
                                f.write(SIGNATURE_DELIMITERS[self.delimiter].join(signaure_data))

                else:
                    self.signatures_meta = {
                        source.name: {'classification': source['default_classification'].value}
                        for source in self._service.update_config.sources
                    }



        # Initialize updater, download signatures, and load them into the service
        updater = TestServiceUpdater()
        updater.do_source_update()
        updater.do_local_update()
        rules_directory = updater.prepare_output_directory()
        service.signatures_meta = updater.signatures_meta
        service.rules_directory = rules_directory
        service.rules_list = [os.path.join(rules_directory, i) for i  in os.listdir(rules_directory)
                            if i != SIGNATURES_META_FILENAME]
        service._load_rules()
