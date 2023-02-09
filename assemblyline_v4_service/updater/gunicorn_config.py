"""
The updater components get all the same environment variables as other core containers.
If these variables are set globally for ui and you don't want it to effect the updaters
they can be overwritten (for all future systems) by setting them in the service manifest
entry for the updater container, or (for a running system) in the service configuration
UI panel for the update container.
"""
from os import environ as env

# Port to bind to
bind = f":{int(env.get('PORT', 5003))}"

# Number of processes to launch
workers = int(env.get('WORKERS', 1))

# Number of concurrent handled connections
threads = int(env.get('THREADS', 4))
worker_connections = int(env.get('WORKER_CONNECTIONS', '1000'))

# Recycle the process after X request randomized by the jitter
max_requests = int(env.get('MAX_REQUESTS', '1000'))
max_requests_jitter = int(env.get('MAX_REQUESTS_JITTER', '100'))

# Connection timeouts
#  - Defaults to double what the poll length for services should be
graceful_timeout = int(env.get('GRACEFUL_TIMEOUT', '60'))
timeout = int(env.get('TIMEOUT', '60'))

# TLS/SSL Configuration
certfile = env.get('CERTFILE')
keyfile = env.get('KEYFILE')
