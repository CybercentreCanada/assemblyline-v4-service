import functools
import os
# 1 background thread for running updates
# 3 allow support containers to request (in manifest) core config
# 4 api for list/downloading update files

from flask import jsonify, make_response, request, send_from_directory, send_file
from werkzeug.exceptions import Unauthorized, ServiceUnavailable

from assemblyline_v4_service.updater.background import BackgroundUpdateApp


app = BackgroundUpdateApp('service_updater')
AUTH_KEY = os.environ.get('SERVICE_API_AUTH_KEY', 'ThisIsARandomAuthKey...ChangeMe!')


@app.route('/healthz/live')
def container_ready():
    """Only meant to convey if the container is running, not if updates are ready."""
    return make_response("OK")


@app.route('/status')
def update_status():
    """A report on readiness for services to run."""
    return make_response(jsonify({
        'initialized': app.service is not None,
        'update_available': app.update_dir() is not None
    }))


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
    path = app.update_dir()
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
    path = app.update_dir()
    if path is None or not os.path.isdir(path):
        raise ServiceUnavailable("No update ready")
    return send_from_directory(path, name)


@app.route('/tar')
@api_login
def get_all_files():
    """Download a tar containing all the files in the current update."""
    path = app.update_tar()
    if path is None or not os.path.isdir(path):
        raise ServiceUnavailable("No update ready")
    return send_file(path)
