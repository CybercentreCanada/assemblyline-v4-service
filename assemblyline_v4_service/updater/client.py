import os

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature as SignatureModel
from assemblyline_core.badlist_client import BadlistClient
from assemblyline_core.safelist_client import SafelistClient
from assemblyline_client import Client4, get_client as get_AL_client
from assemblyline_client.v4_client.module.badlist import Badlist as BadlistAPI
from assemblyline_client.v4_client.module.safelist import Safelist as SafelistAPI
from assemblyline_client.v4_client.module.signature import Signature as SignatureAPI

from typing import Any, Dict, List, Union

SIGNATURE_UPDATE_BATCH = int(os.environ.get('SIGNATURE_UPDATE_BATCH', '1000'))


class Badlist(BadlistAPI):
    def __init__(self, connection, datastore=None):
        super().__init__(connection)
        if not datastore:
            datastore = forge.get_datastore()
        self.badlist_client = BadlistClient(datastore)

    def add_update(self, badlist_object: dict):
        return self.badlist_client.add_update(badlist_object)

    def add_update_many(self, list_of_badlist_object):
        return self.badlist_client.add_update_many(list_of_badlist_object)


class Safelist(SafelistAPI):
    def __init__(self, connection, datastore=None):
        super().__init__(connection)
        if not datastore:
            datastore = forge.get_datastore()
        self.safelist_client = SafelistClient(datastore)

    def add_update(self, safelist_object):
        return self.safelist_client.add_update(safelist_object)

    def add_update_many(self, list_of_safelist_object):
        return self.safelist_client.add_update_many(list_of_safelist_object)


class Signature(SignatureAPI):
    def __init__(self, connection, datastore=None):
        super().__init__(connection)
        self.datastore = datastore
        if not datastore:
            self.datastore = forge.get_datastore()
        self.sync = False

    def add_update_many(self, source: str, sig_type: str, data: List[Union[dict, SignatureModel]],
                        dedup_name: bool = True) -> Dict[str, Any]:
        # This version of the API allows to sync signatures with the system by making direct changes to the datastore
        # Signatures that no longer exist at the source will be DISABLED to maintain active synchronicity,
        # but users can always re-deploy signatures if desired

        current_signature_ids = set()

        # Iterate over the list of signatures given
        for i, d in enumerate(data):
            if isinstance(d, SignatureModel):
                d = d.as_primitives()

            if self.sync:
                # Compute the expected signature ID and add it to the list
                sig_id = f"{sig_type}_{source}_{d['signature_id']}"
                current_signature_ids.add(sig_id)

                # Check to see if there's any important changes made
                sig_exists: SignatureModel = self.datastore.signature.get_if_exists(sig_id, as_obj=False)
                if sig_exists and all(sig_exists[attr] == d[attr] for attr in ['status', 'data', 'classification']):
                    # If no changes, then use the old `last_modified` value
                    d['last_modified'] = sig_exists['last_modified']
                else:
                    # Otherwise a change did happen and this has to be reflected
                    d['last_modified'] = 'NOW'

            # Update with JSON-friendly version of data to be sent to API
            data[i] = d

        if self.sync:
            # Get the list of signatures that currently existing in the system for the source
            existing_signature_ids = set([
                i.id for i in self.datastore.signature.stream_search(f"source:{source} AND type:{sig_type}", fl='id')
            ])

            # Find the signature IDs that don't exist at this source anymore and disable them
            for missing_signature_id in (existing_signature_ids - current_signature_ids):
                missing_signature = self.datastore.signature.get(missing_signature_id)
                if missing_signature.state_change_user in ['update_service_account', None] and \
                        missing_signature.status != 'DISABLED':
                    # Only disable signature if it doesn't seem to be in use/altered by a (real) user
                    self.datastore.signature.update(missing_signature_id,
                                                    [(self.datastore.signature.UPDATE_SET, 'status', 'DISABLED'),
                                                     (self.datastore.signature.UPDATE_SET, 'last_modified', 'NOW')])

        # Proceed with adding/updating signatures via the API server
        if len(data) < SIGNATURE_UPDATE_BATCH:
            # Update all of them in a single batch
            return super().add_update_many(source, sig_type, data, dedup_name)
        else:
            response = {
                'success': 0,
                'errors': False,
                'skipped': []
            }

            def update_response(r: Dict[str, Any]):
                # Response has to be in the same format, but show the accumulation of batches
                response['success']: int = response['success'] + r['success']
                response['errors']: bool = response['errors'] or r['errors']
                response['skipped']: List[str] = response['skipped'] + r['skipped']

            # Split up data into batches to avoid server timeouts handling requests
            batch_num = 0
            start = batch_num*SIGNATURE_UPDATE_BATCH
            while start < len(data):
                end = (batch_num+1)*SIGNATURE_UPDATE_BATCH
                update_response(super().add_update_many(source, sig_type, data[start:end], dedup_name))
                batch_num += 1
                start = batch_num*SIGNATURE_UPDATE_BATCH

            return response


def get_client(server, auth=None, cert=None, debug=lambda x: None, headers=None, retries=0,
               silence_requests_warnings=True, apikey=None, verify=True, timeout=None, oauth=None,
               datastore=None) -> Client4:

    client = get_AL_client(server, auth, cert, debug, headers,
                           retries, silence_requests_warnings,
                           apikey, verify, timeout, oauth)
    # Override module(s) with custom implementation
    client.badlist = Badlist(client._connection, datastore=datastore)
    client.safelist = Safelist(client._connection, datastore=datastore)
    client.signature = Signature(client._connection, datastore=datastore)
    return client
