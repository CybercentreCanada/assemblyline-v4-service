
from assemblyline_v4_service.updater.updater import ServiceUpdater


class SampleUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256, client, source_name, default_classification=None):
        # Do nothing
        return

    # Service base handles the default means of gathering source updates, it's up to the service writer to define
    # how to handle importing the update into Assemblyline

    # do_source_update() of ServiceUpdater class can be overridden if necessary
    # ie. assemblyline-service-safelist


if __name__ == '__main__':
    with SampleUpdateServer() as server:
        server.serve_forever()
