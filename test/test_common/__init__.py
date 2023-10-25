import os
import subprocess

SERVICE_CONFIG_NAME = "service_manifest.yml"
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

ret = subprocess.run("dpkg -l | grep ^ii | awk '{print $2}' | grep -i 'tesseract'", capture_output=True, shell=True)
TESSERACT_LIST = list(filter(None, ret.stdout.decode().split('\n')))

def setup_module():
    open_manifest = open(TEMP_SERVICE_CONFIG_PATH, "w")
    open_manifest.write("\n".join([
        "name: Sample",
        "version: 4.4.0.dev0",
        "docker_config:",
        "    image: sample",
        "heuristics:",
        "  - heur_id: 1",
        "    name: blah",
        "    description: blah",
        "    filetype: '*'",
        "    score: 250",
        "    attack_id: T1005",
        "    max_score: 1200",
        "config:",
        "  ocr:",
        "    banned: [donotscanme]",
        "    macros: []",
        "    ransomware: []",
        "  submission_params:",
        "    - default: blah",
        "      value: blah",
        "      name: thing",
        "      type: str",
    ]))
    open_manifest.close()


def teardown_module():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)
