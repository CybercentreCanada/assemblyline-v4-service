import os
import shutil
import tempfile
import time
from logging import Logger
from shutil import make_archive
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import certifi
import psutil
import regex as re
import requests
from assemblyline_v4_service.common.utils import DEVELOPMENT_MODE
from git import Repo

from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.identify import Identify
from assemblyline.common.isotime import iso_to_epoch

BLOCK_SIZE = 64 * 1024
GIT_ALLOW_UNSAFE_PROTOCOLS = os.environ.get('GIT_ALLOW_UNSAFE_PROTOCOLS', 'false').lower() == 'true'


if DEVELOPMENT_MODE:
    identify = Identify(use_cache=False)
else:
    identify = Identify()


class SkipSource(RuntimeError):
    pass


def add_cacert(cert: str) -> None:
    # Add certificate to requests
    cafile = certifi.where()
    with open(cafile, 'a') as ca_editor:
        ca_editor.write(f"\n{cert}")


def filter_downloads(output_path, pattern, default_pattern=".*") -> List[Tuple[str, str]]:
    if not output_path:
        # Nothing to filter.
        return []

    f_files = []
    if not pattern:
        # Regex will either match on the filename, directory, or filepath,
        # either with default or given pattern for source
        pattern = default_pattern

    if os.path.isfile(output_path):
        if re.match(pattern, output_path):
            return [(output_path, get_sha256_for_file(output_path))]
        return []

    for path_in_dir, subdirs, files in os.walk(output_path):
        for filename in files:
            filepath = os.path.join(path_in_dir, filename)
            if re.match(pattern, filepath) or re.match(pattern, filename):
                f_files.append((filepath, get_sha256_for_file(filepath)))
        for subdir in subdirs:
            dirpath = f'{os.path.join(path_in_dir, subdir)}/'
            if re.match(pattern, dirpath):
                f_files.append((dirpath, get_sha256_for_file(make_archive(subdir, 'tar', root_dir=dirpath))))

    if re.match(pattern, f"{output_path}/"):
        f_files.append((f"{output_path}/", get_sha256_for_file(make_archive(
            os.path.basename(output_path), 'tar', root_dir=output_path))))

    return f_files


def url_download(source: Dict[str, Any], previous_update: int, logger: Logger, output_dir: str) -> Optional[str]:
    name = source['name']
    uri = source['uri']

    # A file_name in the path is expected and required
    if not os.path.basename(urlparse(uri).path):
        raise ValueError(f"Provided source uri does not end with a file name: '{uri}'")

    username = source.get('username', None)
    password = source.get('password', None)
    ca_cert = source.get('ca_cert', None)
    ignore_ssl_errors = source.get('ssl_ignore_errors', False)
    auth = (username, password) if username and password else None

    proxy = source.get('proxy', None)
    headers_list = source.get('headers', [])
    headers = {}
    [headers.update({header['name']: header['value']}) for header in headers_list]

    logger.info(f"{name} source is configured to {'ignore SSL errors' if ignore_ssl_errors else 'verify SSL'}.")
    if ca_cert:
        logger.info("A CA certificate has been provided with this source.")
        add_cacert(ca_cert)

    # Create a requests session
    session = requests.Session()
    session.verify = not ignore_ssl_errors

    # Let https requests go through proxy
    proxies = {'http': proxy, 'https': proxy} if proxy else None

    try:
        response = None
        with tempfile.NamedTemporaryFile('w') as private_key_file:
            if source.get('private_key'):
                logger.info('A private key has been provided with this source')
                private_key_file.write(source['private_key'])
                private_key_file.seek(0)
                session.cert = private_key_file.name

            # Check the response header for the last modified date
            response = session.head(uri, auth=auth, headers=headers, proxies=proxies)
            last_modified = response.headers.get('Last-Modified', None)
            if last_modified:
                # Convert the last modified time to epoch
                last_modified = time.mktime(time.strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z"))

                # Compare the last modified time with the last updated time
                if previous_update and last_modified <= previous_update:
                    # File has not been modified since last update, do nothing
                    raise SkipSource()

            if previous_update:
                previous_update = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(previous_update))
                if headers:
                    headers['If-Modified-Since'] = previous_update
                else:
                    headers = {'If-Modified-Since': previous_update}

            response = session.get(uri, auth=auth, headers=headers, proxies=proxies, stream=True)

        # Check the response code
        if response.status_code == requests.codes['not_modified']:
            # File has not been modified since last update, do nothing
            raise SkipSource()
        elif response.ok:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            file_name = os.path.basename(urlparse(uri).path)
            file_path = os.path.join(output_dir, file_name)
            with open(file_path, 'wb') as f:
                for content in response.iter_content(BLOCK_SIZE):
                    f.write(content)

            ident_type = identify.fileinfo(file_path, generate_hashes=False)['type']
            if ident_type.startswith('archive'):
                extract_dir = os.path.join(output_dir, name)
                format = ident_type.split('archive/')[-1]

                # Make sure identified format is supported by the library
                format = format if format in ["zip", "tar"] else None
                shutil.unpack_archive(file_path, extract_dir=extract_dir, format=format)

                return extract_dir
            else:
                return file_path
        else:
            logger.warning(f"Download not successful: {response.content}")
            return None

    except SkipSource:
        # Raise to calling function for handling
        raise
    except Exception as e:
        # Catch all other types of exceptions such as ConnectionError, ProxyError, etc.
        raise e
    finally:
        # Close the requests session
        session.close()


def git_clone_repo(source: Dict[str, Any], previous_update: int = None, logger=None, output_dir: str = None) -> str:
    name = source['name']
    url = source['uri']
    key = source.get('private_key', None)
    username = source.get('username', None)
    password = source.get('password', None)
    branch = source.get('git_branch', None) or None

    ignore_ssl_errors = source.get("ssl_ignore_errors", False)
    ca_cert = source.get("ca_cert")
    proxy = source.get('proxy', None)
    auth = f'{username}:{password}@' if username and password else None

    git_env = {}

    if ignore_ssl_errors:
        git_env['GIT_SSL_NO_VERIFY'] = '1'

    # Let https requests go through proxy
    if proxy:
        git_env['https_proxy'] = proxy

    if ca_cert:
        logger.info("A CA certificate has been provided with this source.")
        add_cacert(ca_cert)
        git_env['GIT_SSL_CAINFO'] = certifi.where()

    if auth:
        logger.info("Credentials provided for auth..")
        url = re.sub(r'^(?P<scheme>https?://)', fr'\g<scheme>{auth}', url)

    clone_dir = os.path.join(output_dir, name)
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)

    try:
        with tempfile.NamedTemporaryFile() as git_ssh_identity_file:
            if key:
                logger.info(f"key found for {url}")
                # Save the key to a file
                git_ssh_identity_file.write(key.encode())
                git_ssh_identity_file.seek(0)
                os.chmod(git_ssh_identity_file.name, 0o0400)

                git_ssh_cmd = f"ssh -oStrictHostKeyChecking=no -i {git_ssh_identity_file.name}"
                git_env['GIT_SSH_COMMAND'] = git_ssh_cmd

            # As checking for .git at the end of the URI is not reliable
            # we will use the exception to determine if its a git repo or direct download.
            repo = Repo.clone_from(url, clone_dir, env=git_env, branch=branch,
                                   allow_unsafe_protocols=GIT_ALLOW_UNSAFE_PROTOCOLS, depth=1)

            # Check repo last commit
            if previous_update:
                if isinstance(previous_update, str):
                    previous_update = iso_to_epoch(previous_update)
                for c in repo.iter_commits():
                    if c.committed_date < previous_update:
                        raise SkipSource()
                    break

        return clone_dir
    except SkipSource:
        # Raise to calling function for handling
        raise
    except Exception as e:
        # Catch all other types of exceptions such as ConnectionError, ProxyError, etc.
        raise e
    finally:
        # Cleanup any lingering Git zombies
        for p in psutil.process_iter():
            if 'git' in p.name() and p.status() == 'zombie':
                p.terminate()
                p.wait()
                break
