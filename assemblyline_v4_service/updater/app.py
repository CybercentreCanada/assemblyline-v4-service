import functools
import os

from flask import jsonify, make_response, request, send_from_directory, send_file, Flask
from werkzeug.exceptions import Unauthorized, ServiceUnavailable

from .updater import ServiceUpdater, UpdaterRPC, MANAGER_KEY, MANAGER_PORT, MANAGER_HOST

# The real ServiceUpdater object is running in a different process from 
# the http interface. Exported methods of the process can be accessed via the
# proxy object 'updater' below. 
server = UpdaterRPC(address=(MANAGER_HOST, MANAGER_PORT), authkey=MANAGER_KEY)
server.connect()
updater: ServiceUpdater = getattr(server, 'updater')()


app = Flask('service_updater')
AUTH_KEY = os.environ.get('SERVICE_API_AUTH_KEY', 'ThisIsARandomAuthKey...ChangeMe!')


@app.route('/healthz/live')
def container_ready():
    """Only meant to convey if the container is running, not if updates are ready."""
    return make_response("OK")


@app.route('/status')
def update_status():
    """A report on readiness for services to run."""
    return make_response(jsonify(updater.status()))


def api_login(func):
    @functools.wraps(func)
    def base(*args, **kwargs):
        # Before anything else, check that the API key is set
        apikey = request.environ.get('HTTP_X_APIKEY', None)
        if AUTH_KEY != apikey:
            app.logger.warning(f'Client provided wrong api key [{apikey}]')
            raise Unauthorized("Unauthorized access denied")
        return func(*args, **kwargs)

    return base


@app.route('/files')
@api_login
def list_files():
    """Get a directory listing of files in the current update."""
    path = updater.update_directory()
    if path is None or not os.path.isdir(path):
        raise ServiceUnavailable("No update ready")

    entries = []
    for dirname, _, file_names in os.walk(path):
        entries.extend([os.path.join(dirname, _f) for _f in file_names])

    return make_response(jsonify({
        'files': entries
    }))


@app.route('/files/<path:name>')
@api_login
def get_file(name):
    """Download a specific file from the directory listing of the current update."""
    path = updater.update_directory()
    if path is None or not os.path.isdir(path):
        raise ServiceUnavailable("No update ready")
    return send_from_directory(path, name)


@app.route('/tar')
@api_login
def get_all_files():
    """Download a tar containing all the files in the current update."""
    path = updater.update_tar()
    if path is None or not os.path.isfile(path):
        raise ServiceUnavailable("No update ready")
    return send_file(path)


if __name__ == '__main__':
    app.run()
