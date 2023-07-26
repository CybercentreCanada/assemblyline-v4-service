import os

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature as SignatureModel
from assemblyline_client import Client4, get_client as get_AL_client
from assemblyline_client.v4_client.module.signature import Signature as SignatureAPI

from typing import List, Union

SIGNATURE_UPDATE_BATCH = int(os.environ.get('SIGNATURE_UPDATE_BATCH', '1000'))


class Signature(SignatureAPI):
    def __init__(self, connection, logger):
        super().__init__(connection)
        self.datastore = forge.get_datastore()
        self.log = logger

    def add_update_many(self, source: str, sig_type: str, data: List[Union[dict, SignatureModel]], dedup_name=True):
        # This version of the API will sync signatures with the system by making direct changes to the datastore
        # Signatures that no longer exist at the source will be DISABLED, but users can always re-deploy signatures if desired

        # Get the list of signatures that currently existing in the system for the source
        existing_signature_ids = set([
            i.id for i in self.datastore.signature.stream_search(f'source:{source} AND type:{sig_type}', fl='id')
            ])
        current_signature_ids = set()

        data_to_send = []
        # Iterate over the data given
        for d in data:
            if isinstance(d, SignatureModel):
                d = d.as_primitives()

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

            # Append JSON-friendly data to be sent to API
            data_to_send.append(d)

        # Find the signature IDs that don't exist at this source anymore and disable them
        for missing_signature_id in (existing_signature_ids - current_signature_ids):
            missing_signature = self.datastore.signature.get(missing_signature_id)
            if missing_signature.state_change_user in ['update_service_account', None] and missing_signature.status != 'DISABLED':
                # Only disable signature if it doesn't seem to be in use/altered by a (real) user
                self.datastore.signature.update(missing_signature_id,
                                                [(self.datastore.signature.UPDATE_SET, 'status', 'DISABLED'),
                                                 (self.datastore.signature.UPDATE_SET, 'last_modified', 'NOW')])

        # Proceed with adding/updating signatures via the API server
        if len(data_to_send) < SIGNATURE_UPDATE_BATCH:
            # Update all of them in a single batch
            return super().add_update_many(source, sig_type, data_to_send, dedup_name)
        else:
            response = {
                'success': 0,
                'errors': [],
                'skipped': []
            }

            def update_response(r):
                # Response has to be in the same format, but show the accumulation of batches
                response['success'] = response['success'] + r['success']
                response['errors'] = response['errors'] + r['errors']
                response['success'] = response['skipped'] + r['skipped']

            # Split up data into batches to avoid server timeouts handling requests
            batch_num = 0
            start = batch_num*SIGNATURE_UPDATE_BATCH
            while start < len(data_to_send):
                end = (batch_num+1)*SIGNATURE_UPDATE_BATCH
                update_response(super().add_update_many(source, sig_type, data_to_send[start:end], dedup_name))
                batch_num += 1

            return response


class UpdaterALClient(Client4):
    # Custom version of the Assemblyline client specifically for updaters
    def __init__(self, connection, logger):
        super().__init__(connection)
        self.signature = Signature(connection, logger)

    @staticmethod
    def get_client(server, auth=None, cert=None, debug=lambda x: None, headers=None, retries=0,
                   silence_requests_warnings=True, apikey=None, verify=True, timeout=None, oauth=None,
                   logger=None):
        return UpdaterALClient(get_AL_client(server, auth, cert, debug, headers,
                                             retries, silence_requests_warnings,
                                             apikey, verify, timeout, oauth)._connection, logger=logger)
