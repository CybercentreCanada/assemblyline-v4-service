#!/usr/bin/env python

# Run a standalone AL service

import json
import logging
import os
import tempfile
import time

import pyinotify
import yaml

from assemblyline.common import log as al_log
from assemblyline.common.dict_utils import recursive_update
from assemblyline.common.importing import load_module_by_path
from assemblyline.odm.messages.task import Task

task_found = False


class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        global task_found

        task_path = os.path.join(event.pathname, 'task.json')
        while not os.path.exists(task_path):
            time.sleep(0.1)
        task_found = True


def run_service():
    global task_found

    service = svc_class(cfg)
    service.start_service()

    folder_path = os.path.join(tempfile.gettempdir(), svc_name, 'received')

    if not os.path.isdir(folder_path):
        os.makedirs(folder_path)

    wm = pyinotify.WatchManager()  # Watch Manager
    notifier = pyinotify.ThreadedNotifier(wm, EventHandler())

    try:
        notifier.start()

        while True:
            # Check if 'received' directory already contains a task
            if os.listdir(folder_path):
                task_found = True
            else:
                wdd = wm.add_watch(folder_path, pyinotify.IN_CREATE, rec=True)

            while not task_found:
                # log.info('Waiting for task in: {}'.format(folder_path))
                time.sleep(2)

            task_found = False

            try:
                wm.rm_watch(wdd.values())
            except:
                pass

            for task in os.listdir(folder_path):
                task_path = os.path.join(folder_path, task, 'task.json')
                log.info(f"Task found in: {task_path}")
                with open(task_path, 'r') as f:
                    task = Task(json.load(f))
                service.handle_task(task)
    finally:
        notifier.stop()
        service.stop_service()


def get_service_config(yml_config=None):
    if yml_config is None:
        yml_config = "/etc/assemblyline/service_config.yml"

    default_file = os.path.join(os.path.dirname(__file__), "common", "service_config.yml")
    if os.path.exists(default_file):
        with open(default_file, 'r') as default_fh:
            service_config = yaml.safe_load(default_fh.read())

    # Load modifiers from the service
    service = svc_class()
    service_data = service.get_default_config()
    service_config = recursive_update(service_config, service_data)
    service_config['SERVICE_TOOL_VERSION'] = service.get_tool_version()

    with open(yml_config, 'w') as yml_fh:
        yaml.safe_dump(service_config, yml_fh)

    return service_config['SERVICE_DEFAULT_CONFIG']


if __name__ == '__main__':

    name = os.environ['SERVICE_PATH']

    svc_name = name.split(".")[-1].lower()
    al_log.init_logging(log_level=logging.INFO)
    log = logging.getLogger(f"assemblyline.svc.{svc_name}")

    try:
        svc_class = load_module_by_path(name)
    except:
        log.error("Could not find service in path.")
        raise

    cfg = get_service_config()
    run_service()
