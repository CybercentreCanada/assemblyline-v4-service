from assemblyline_v4_service.updater.updater import ServiceUpdater


with ServiceUpdater() as instance:
    instance.serve_forever()
