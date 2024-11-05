import random
import pytest

from assemblyline.odm.random_data import create_badlists, create_safelists, create_signatures, wipe_badlist, wipe_safelist, wipe_signatures
from assemblyline_v4_service.updater.client import UpdaterClient


@pytest.fixture(scope="module")
def client(datastore_connection):
    try:
        create_badlists(datastore_connection)
        create_safelists(datastore_connection)
        create_signatures(datastore_connection)
        yield UpdaterClient(datastore_connection)
    finally:
        wipe_badlist(datastore_connection)
        wipe_safelist(datastore_connection)
        wipe_signatures(datastore_connection)


@pytest.mark.parametrize("hashlist", ["badlist", "safelist"])
def test_hashlist_sync(client, hashlist):
    hashlist_collection = getattr(client.datastore, hashlist)

    # Pick an arbitrary source name fron the hashlist collection
    SOURCE_NAME = random.choice(list(hashlist_collection.facet("sources.name",
                                                               query="sources.type:external AND enabled:true").keys()))

    # Get the set of items that are currently enabled in the test source
    items = [
        i
        for i in hashlist_collection.stream_search(
            query=f"sources.name:{SOURCE_NAME} AND enabled:true",
            fl="id,sources")
    ]

    # Get a single item to be used during update
    update_id = items.pop(0).id
    update_item = hashlist_collection.get(update_id)

    # Turn on syncing with the client
    client.sync = True

    # Perform update with no items found in source on update (this isn't allowed and will result in zero changes)
    assert getattr(client, hashlist).add_update_many(data=[]) == {"success": 0, "errors": False}

    # Perform updates with a single item found in source
    assert getattr(client, hashlist).add_update_many(data=[update_item]) == {"success": 1, "errors": False}

    # Ensure changes to items are as expected
    for item in items:
        item = hashlist_collection.get(item.id)
        if item.enabled:
            # If the item is still enabled, then we have to ensure the test source was removed from the source list
            assert all([not (s.name == SOURCE_NAME and s.type == 'external') for s in item.sources])
        else:
            # If the item has been disabled, then we have to ensure there is only one source left in the source list
            assert len(item.sources) == 1


def test_signature_sync(client):
    # Get the set of YARA signatures that are currently DEPLOYED in the YAR_SAMPLE source
    SOURCE_NAME = "YAR_SAMPLE"
    SIG_TYPE = "yara"
    signature_ids = [
        i.id
        for i in client.datastore.signature.stream_search(
            query=f"source:{SOURCE_NAME} AND type:{SIG_TYPE} AND status:DEPLOYED",
            fl="id")
    ]

    # Turn on syncing with the client
    client.sync = True

    # Simulate if all the signatures from the source is missing on update
    client.signature.add_update_many(SOURCE_NAME, SIG_TYPE, data=[])

    # Assert that all signatures that were previously DEPLOYED are now all DISABLED
    assert all([client.datastore.signature.get(id).status == "DISABLED" for id in signature_ids])

def test_signature_update(client):
    # Get the set of YARA signatures that are currently DEPLOYED in the YAR_SAMPLE source
    SOURCE_NAME = "YAR_SAMPLE"
    SIG_TYPE = "yara"
    signatures = [
        i
        for i in client.datastore.signature.search(query=f"source:{SOURCE_NAME} AND type:{SIG_TYPE}", rows=5, fl="id,*")['items']
    ]
    signature_ids = [s.id for s in signatures]

    # Simulate if a user changed all the signatures and change the signature status
    for s in signatures:
        client.datastore.signature.update(s.id, [(client.datastore.signature.UPDATE_SET, 'state_change_user', 'test')])
        s.status = "INVALID"
    client.signature.add_update_many(SOURCE_NAME, SIG_TYPE, data=signatures)

    # Assert that all signatures that were modified by a user retains their original status
    for signature_id in signature_ids:
        signature = client.datastore.signature.get(signature_id)
        assert signature.status != "INVALID" and signature.state_change_user == "test"
