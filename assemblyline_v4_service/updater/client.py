import os

from assemblyline.odm.models.badlist import Badlist as BadlistModel
from assemblyline.odm.models.safelist import Safelist as SafelistModel
from assemblyline.odm.models.signature import Signature as SignatureModel
from assemblyline_core.badlist_client import BadlistClient
from assemblyline_core.safelist_client import SafelistClient
from assemblyline_core.signature_client import SignatureClient

from typing import Any, Dict, List, Union

SIGNATURE_UPDATE_BATCH = int(os.environ.get('SIGNATURE_UPDATE_BATCH', '1000'))


class SyncableBadlistClient(BadlistClient):
    def __init__(self, datastore, config=None):
        super().__init__(datastore, config)
        self.sync = False

    def add_update_many(self, data: List[Union[dict, BadlistModel]]) -> Dict[str, Any]:
        # This version of the API allows to sync badlist items with the system by making direct changes to the datastore
        # Items that no longer exist at the source will be removed from `sources` to maintain active synchronicity
        # amongst multiple sources.
        # If there are no more sources actively blocking the item, then the item will be DISABLED but users can always
        # re-deploy item if desired

        current_ids = set()
        source = None

        # Iterate over the list of signatures given
        for i, d in enumerate(data):
            if isinstance(d, BadlistModel):
                d = d.as_primitives()

            if not source:
                # Set the source name
                source = data["sources"][0]["name"]

            if self.sync:
                # Compute the expected badlist ID and add it to the list
                current_ids.add(self._preprocess_object(d))

            # Update with JSON-friendly version of data to be sent to API
            data[i] = d

        if self.sync:
            # Get the list of items that currently existing in the system for the source
            existing_ids = set(
                [
                    i["id"]
                    for i in self.datastore.badlist.stream_search(
                        f"sources.name:{source}", fl="id", as_obj=False
                    )
                ]
            )

            # Find the IDs that don't exist at this source anymore and remove the source from the source list
            for missing_id in existing_ids - current_ids:
                missing_item: BadlistModel = self.datastore.badlist.get(missing_id)
                missing_item.sources = [
                    s
                    for s in missing_item.sources
                    if not (s.type == "external" and s.name == source)
                ]

                # If there are no more sources to back this item, then disable it
                if not missing_item.sources:
                    missing_item.enabled = False

                # Update missing item with latest changes
                self.datastore.badlist.save(missing_id, missing_item)

        # Proceed with adding/updating items
        if len(data) < SIGNATURE_UPDATE_BATCH:
            # Update all of them in a single batch
            return super().add_update_many(data)
        else:
            response = {"success": 0, "errors": []}

            def update_response(r: Dict[str, Any]):
                # Response has to be in the same format, but show the accumulation of batches
                response["success"]: int = response["success"] + r["success"]
                response["errors"]: List[str] = response["errors"] + r["errors"]

            # Split up data into batches to avoid server timeouts handling requests
            batch_num = 0
            start = batch_num * SIGNATURE_UPDATE_BATCH
            while start < len(data):
                end = (batch_num + 1) * SIGNATURE_UPDATE_BATCH
                update_response(super().add_update_many(data[start:end]))
                batch_num += 1
                start = batch_num * SIGNATURE_UPDATE_BATCH

            return response


class SyncableSafelistClient(SafelistClient):
    def __init__(self, datastore, config=None):
        super().__init__(datastore, config)
        self.sync = False

    def add_update_many(self, data: List[Union[dict, SafelistModel]]) -> Dict[str, Any]:
        # This version of the API allows to sync safelist items with the system by making direct changes to the datastore
        # Items that no longer exist at the source will be removed from `sources` to maintain active synchronicity
        # amongst multiple sources.
        # If there are no more sources actively safelisting the item, then the item will be DISABLED but users can always
        # re-deploy item if desired

        current_ids = set()
        source = None

        # Iterate over the list of signatures given
        for i, d in enumerate(data):
            if isinstance(d, SafelistModel):
                d = d.as_primitives()

            if not source:
                # Set the source name
                source = data["sources"][0]["name"]

            if self.sync:
                # Compute the expected safelist ID and add it to the list
                current_ids.add(self._preprocess_object(d))

            # Update with JSON-friendly version of data to be sent to API
            data[i] = d

        if self.sync:
            # Get the list of items that currently existing in the system for the source
            existing_ids = set(
                [
                    i["id"]
                    for i in self.datastore.safelist.stream_search(
                        f"sources.name:{source}", fl="id", as_obj=False
                    )
                ]
            )

            # Find the IDs that don't exist at this source anymore and remove the source from the source list
            for missing_id in existing_ids - current_ids:
                missing_item: SafelistModel = self.datastore.safelist.get(missing_id)
                missing_item.sources = [
                    s
                    for s in missing_item.sources
                    if not (s.type == "external" and s.name == source)
                ]

                # If there are no more sources to back this item, then disable it
                if not missing_item.sources:
                    missing_item.enabled = False

                # Update missing item with latest changes
                self.datastore.safelist.save(missing_id, missing_item)

        # Proceed with adding/updating items
        if len(data) < SIGNATURE_UPDATE_BATCH:
            # Update all of them in a single batch
            return super().add_update_many(data)
        else:
            response = {"success": 0, "errors": []}

            def update_response(r: Dict[str, Any]):
                # Response has to be in the same format, but show the accumulation of batches
                response["success"]: int = response["success"] + r["success"]
                response["errors"]: List[str] = response["errors"] + r["errors"]

            # Split up data into batches to avoid server timeouts handling requests
            batch_num = 0
            start = batch_num * SIGNATURE_UPDATE_BATCH
            while start < len(data):
                end = (batch_num + 1) * SIGNATURE_UPDATE_BATCH
                update_response(super().add_update_many(data[start:end]))
                batch_num += 1
                start = batch_num * SIGNATURE_UPDATE_BATCH

            return response


class SyncableSignatureClient(SignatureClient):
    def __init__(self, datastore, config=None):
        super().__init__(datastore, config)
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

        # Proceed with adding/updating signatures
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
            start = batch_num * SIGNATURE_UPDATE_BATCH
            while start < len(data):
                end = (batch_num + 1) * SIGNATURE_UPDATE_BATCH
                update_response(super().add_update_many(source, sig_type, data[start:end], dedup_name))
                batch_num += 1
                start = batch_num * SIGNATURE_UPDATE_BATCH

            return response


class UpdaterClient(object):
    def __init__(self, datastore) -> None:
        self.datastore = datastore
        self._sync = False
        self.badlist = SyncableBadlistClient(datastore)
        self.safelist = SyncableSafelistClient(datastore)
        self.signature = SyncableSignatureClient(datastore)

    @property
    def sync(self):
        return self._sync

    @sync.setter
    def sync(self, value: bool):
        # Set sync state across clients
        self.badlist.sync = self.safelist.sync = self.signature.sync = self._sync = value
