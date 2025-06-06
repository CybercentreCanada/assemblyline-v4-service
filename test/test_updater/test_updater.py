import json
import os
import random
import tempfile

import pytest
from assemblyline_v4_service.updater.updater import (
    SERVICE_NAME,
    SIGNATURES_META_FILENAME,
    SOURCE_STATUS_KEY,
    SOURCE_UPDATE_TIME_KEY,
    ServiceUpdater,
)

from assemblyline.odm.models.service import Service
from assemblyline.odm.models.service_delta import ServiceDelta
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.randomizer import random_model_obj

os.environ['SERVICE_PATH'] = SERVICE_NAME

class TestUpdater(ServiceUpdater):
    def import_update(self, files_sha256, source_name, default_classification=None, configuration = ...): ...

@pytest.fixture()
def updater():
    # Instantiate instance of updater
    updater = TestUpdater()

    # Populate datastore with information about the service
    service = random_model_obj(Service)
    service_delta = random_model_obj(ServiceDelta)
    service.name = SERVICE_NAME
    service_delta.name = SERVICE_NAME
    service_delta.version = "test"
    updater.datastore.service.save(f"{SERVICE_NAME}_test", service)
    updater.datastore.service.commit()
    updater.datastore.service_delta.save(SERVICE_NAME, service_delta)
    updater.datastore.service_delta.commit()

    yield updater


@pytest.fixture()
def initialized_updater(updater: ServiceUpdater):
    # Sync settings from the datastore
    updater._pull_settings()

    # Initialize status for source updates
    updater.update_data_hash.delete()
    for update in updater._service.update_config.sources:
        updater.update_data_hash.set(f"{update.name}.{SOURCE_STATUS_KEY}",
                                     dict(state='TESTING', message='Queued for update..', ts=0))
    yield updater



def test_init(updater: ServiceUpdater):
    # Ensure updater can be initialized when provided the expected environment variables
    assert updater.updater_type == SERVICE_NAME

def test_pull_settings(updater: ServiceUpdater):
    # When first initialized, the updater doesn't have any information about the service
    assert not updater._service

    # Sync settings from the datastore
    updater._pull_settings()

    assert updater._service and updater._service.name == SERVICE_NAME

def test_inventory_check(initialized_updater: ServiceUpdater):
    # There is currently no updates being distributed so it's too early to perform an inventory check
    assert not initialized_updater._update_dir and not initialized_updater._inventory_check()

    # Simulate a update directory (with missing updates)
    with tempfile.TemporaryDirectory() as dir:
        initialized_updater._update_dir = dir

        # If the other thread performing source updates is running, then we have to wait until it's completed before tasking missing sources
        assert initialized_updater.source_update_flag.is_set() and not initialized_updater._inventory_check() and not initialized_updater.update_queue.qsize()

        # Simulate if the source update thread is idle
        initialized_updater.source_update_flag.clear()

        # Expect the inventory check to fail and there should be tasking for all the sources to be fetched
        assert not initialized_updater._inventory_check() and initialized_updater.update_queue.qsize() == len(initialized_updater._service.update_config.sources)

        # Simulate a scenario where the inventory check will pass (there is at least one update available for distribution)
        with tempfile.NamedTemporaryFile(dir=dir, suffix=random.choice(initialized_updater._service.update_config.sources).name):
            assert initialized_updater._inventory_check()

@pytest.mark.parametrize("generates_signatures", [True, False])
def test_do_local_update(initialized_updater, generates_signatures):
    initialized_updater._service.update_config.generates_signatures = generates_signatures
    if generates_signatures:
        # We're expecting the output directory to contain files named after each source

        # Populate some signatures for each source
        sources = [s.name for s in initialized_updater._service.update_config.sources]
        signatures = []
        for update in sources:
            sig = random_model_obj(Signature)
            sig.source = update
            sig.type = SERVICE_NAME
            sig.status = "DEPLOYED"
            signatures.append(sig)
            initialized_updater.client.signature.add_update_many(update, initialized_updater.updater_type, [sig])

        # Perform local update
        initialized_updater.do_local_update()

        # Ensure the update directory is set
        assert initialized_updater._update_dir

        # Check the directory structure is what we're expecting exists
        # -- <update_directory>/
        # | -- service/
        #   | <update_source>
        #   | ...

        service_updates = os.path.join(initialized_updater._update_dir, SERVICE_NAME)
        assert os.path.exists(service_updates) and \
            all([os.path.exists(os.path.join(service_updates, source)) for source in sources])

        # Check that all signatures can be found in signature meta map
        with open(os.path.join(initialized_updater._update_dir, SIGNATURES_META_FILENAME)) as meta_file:
            sig_meta = json.load(meta_file)

            for s in initialized_updater.datastore.signature.stream_search(f"type:{SERVICE_NAME}", fl="signature_id"):
                assert s.signature_id in sig_meta

def test_do_source_update(initialized_updater: ServiceUpdater):
    source = initialized_updater._service.update_config.sources[0]
    update_data_hash = initialized_updater.update_data_hash
    def task_source_update(field, value):
        initialized_updater.update_queue.put(source.name)
        source[field] = value
        initialized_updater.do_source_update(initialized_updater._service)
        return update_data_hash.get(f"{source.name}.{SOURCE_UPDATE_TIME_KEY}"), \
            update_data_hash.get(f"{source.name}.{SOURCE_STATUS_KEY}")

    with tempfile.NamedTemporaryFile() as source_file:
        source.uri = f"file://{source_file.name}"
        source.update_interval = 3600

        # If a source is disabled, we'll skip until it's re-enabled
        update_time, update_state = task_source_update("enabled", False)
        assert update_time is None and update_state["message"] == "Skipped."

        update_time, update_state = task_source_update("enabled", True)
        assert update_time > 0 and update_state["message"] == "Signature(s) Imported."

        # If the we're using source caching, then we should skip if it's too soon to perform the next update
        old_update_time = update_time
        update_time, update_state = task_source_update("ignore_cache", False)
        assert old_update_time == update_time and update_state["message"] == "Skipped."

        # Otherwise we should be able to fetch from the source immediately
        update_time, update_state = task_source_update("ignore_cache", True)
        assert old_update_time < update_time and update_state["message"] == "Signature(s) Imported."
