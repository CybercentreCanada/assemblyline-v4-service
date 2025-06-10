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

from assemblyline.odm.messages.changes import Operation, ServiceChange, SignatureChange
from assemblyline.odm.models.service import Service, UpdateSource
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
    datastore = updater.datastore

    # Populate datastore with information about the service
    service = random_model_obj(Service)
    service_delta = random_model_obj(ServiceDelta)
    service.name = SERVICE_NAME
    service_delta.name = SERVICE_NAME
    service_delta.version = "test"

    # Populate the system with some signatures related to sources configured for the service
    service_delta.update_config.sources = [random_model_obj(UpdateSource, as_json=True)
                                           for _ in range(random.randint(1, 3))]

    # Populate a set of signatures tied to each source
    for source in service_delta.update_config.sources:
        for _ in range(random.randint(1, 5)):
            signature = random_model_obj(Signature)
            signature.type = updater.updater_type
            signature.source = source.name
            datastore.signature.save(signature.signature_id, signature)

    datastore.signature.commit()
    datastore.service.save(f"{SERVICE_NAME}_test", service)
    datastore.service.commit()
    datastore.service_delta.save(SERVICE_NAME, service_delta)
    datastore.service_delta.commit()



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

@pytest.mark.parametrize("operation", [op.value for op in Operation],
                         ids=[f"op={op.name}" for op in Operation])
def test_service_change(initialized_updater: ServiceUpdater, operation):
    # Make a change to service (ie. adding a source to the list)
    datastore = initialized_updater.datastore
    source = random_model_obj(UpdateSource).as_primitives()
    datastore.service_delta.update(SERVICE_NAME, [(datastore.service_delta.UPDATE_APPEND, "update_config.sources", source)])

    # Simulate getting an event from the API notifying that a service change was made
    initialized_updater._handle_service_change_event(ServiceChange("", operation))
    new_settings = initialized_updater._service

    if operation == Operation.Modified:
        # We expect the changes to the service are detected by updater
        assert source in new_settings.update_config.sources

        # We also expect the source update flag to be set to trigger fetching of the new source added
        assert initialized_updater.source_update_flag.is_set()

    # Otherwise on changes that result in the service being Added, Removed, or Incompatible
    # We expect the updater to do nothing as these changes would be more relevant to other parts of the system (ie. Scaler) that are watching the same event stream

@pytest.mark.parametrize("operation", [op.value for op in Operation],
                         ids=[f"op={op.name}" for op in Operation])
def test_signature_change(initialized_updater: ServiceUpdater, operation):
    datastore = initialized_updater.datastore
    initialized_updater._service.update_config.generates_signatures = True
    initialized_updater._service.update_config.signature_delimiter = "double_new_line"

    signature = None
    if operation == Operation.Added:
        # Add a signature to the collection
        signature = random_model_obj(Signature).as_primitives()
        signature["type"] = initialized_updater.updater_type
        signature["status"] = "DEPLOYED"
        datastore.signature.save(signature["signature_id"], signature)

    elif operation == Operation.Modified:
        # Modify an existing signature
        signature = datastore.signature.search(f"type:{initialized_updater.updater_type}", rows=1,
                                               fl="source,signature_id", as_obj=False)['items'][0]
        datastore.signature.update(signature["signature_id"], [(datastore.signature.UPDATE_SET, 'status', "DEPLOYED")])

    elif operation == Operation.Removed:
        # Remove signature source from the system
        signature = datastore.signature.search(f"type:{initialized_updater.updater_type}", rows=1,
                                               fl="signature_id,source", as_obj=False)['items'][0]
        signature["signature_id"] = "*"

        datastore.signature.delete_by_query(f"type:{initialized_updater.updater_type} AND source:{signature['source']}")
    else:
        # Ignore Incompatible operation
        return

    # Commit changes made to index
    datastore.signature.commit()

    # Trigger signature event to be registered by updater
    initialized_updater._handle_signature_change_event(SignatureChange(
        signature_id=signature["signature_id"],
        signature_type=initialized_updater.updater_type,
        source=signature["source"],
        operation=operation
    ))

    # Expect do_local_update flag to be set
    assert initialized_updater.local_update_flag.is_set()

    # Initialize local update and check what happened
    initialized_updater.do_local_update()

    metadata_file = os.path.join(initialized_updater._update_dir, SIGNATURES_META_FILENAME)
    source_file = os.path.join(initialized_updater._update_dir, initialized_updater.updater_type, signature["source"])

    # Based on the operation that took place, we'll need to check the updates carefully
    if operation == Operation.Added:
        # We expect to find the new signature in the latest update
        with open(source_file) as file:
            assert signature["data"] in file.read()

        # We also expect the sigature meta map to include information on this signature
        with open(metadata_file) as meta_file:
            assert signature["signature_id"] in json.load(meta_file)

    elif operation == Operation.Modified:
        # We expect the signature metadata to have changed
        with open(metadata_file) as meta_file:
            meta = json.load(meta_file).get(signature["signature_id"])

            # Assert metadata pertaining to the signature exists and the change was recognized
            assert meta and meta['status'] == "DEPLOYED"
    elif operation == Operation.Removed:
        # We expect the signature source to not exist in the new update
        assert not os.path.exists(source_file)

        # We expect there are no signatures containing metadata related to the source that was deleted
        with open(metadata_file) as meta_file:
            meta = json.load(meta_file)
            assert all(signature["source"] != metadata.get("source") for metadata in meta.values())

def test_source_change(initialized_updater):
    import string
    # Provide a random list of update sources to task the updater
    number_of_updates = random.randint(1,5)
    data = random.choices(string.ascii_letters, k=number_of_updates)

    # Task the updater to trigger and update from sources
    initialized_updater._handle_source_update_event(data)

    # Expect the length of the queue to match the data input
    assert initialized_updater.update_queue.qsize() == number_of_updates

    # Expect the source_update_flag to be set
    assert initialized_updater.source_update_flag.is_set()
