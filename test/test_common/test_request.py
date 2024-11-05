import os
import tempfile
from logging import Logger
from test.test_common import TESSERACT_LIST, setup_module

import pytest
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, get_heuristic_primitives
from assemblyline_v4_service.common.task import MaxExtractedExceeded, Task

from assemblyline.odm.messages.task import Task as ServiceTask

# Ensure service manifest is instantiated before importing from OCR submodule
setup_module()


@pytest.fixture
def service_request():
    st = ServiceTask({
        "service_config": {},
        "metadata": {},
        "min_classification": "",
        "fileinfo": {
            "magic": "blah",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "size": 0,
            "type": "text/plain",
        },
        "filename": "blah",
        "service_name": "blah",
        "max_files": 0,
    })
    t = Task(st)
    service_request = ServiceRequest(t)
    return service_request


def test_init(service_request):
    assert isinstance(service_request.log, Logger)
    assert os.path.exists(service_request._working_directory)
    assert service_request.deep_scan is False
    assert service_request.extracted == []
    assert service_request.file_name == "blah"
    assert service_request.file_type == "text/plain"
    assert service_request.file_size == 0
    assert service_request._file_path is None
    assert service_request.max_extracted == 0
    assert service_request.md5 == "d41d8cd98f00b204e9800998ecf8427e"
    assert service_request.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert service_request.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert isinstance(service_request.sid, str)
    assert isinstance(service_request.task, Task)


def test_add_extracted(service_request):

    # Bare minimum, empty file is ignored
    _, path = tempfile.mkstemp()
    service_request.add_extracted(path, "name", "description")
    assert service_request.extracted == []

    with open(path, "w") as f:
        f.write("test")

    # Now the file is not empty
    service_request.add_extracted(path, "name", "description")
    assert service_request.extracted == [
        {
            'allow_dynamic_recursion': False,
            'classification': 'TLP:C',
            'description': 'description',
            'is_section_image': False,
            'is_supplementary': False,
            'name': 'name',
            'parent_relation': 'EXTRACTED',
            'path': path,
            'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
        },
    ]

    # Raise MaxExtractedExceeded
    service_request.task.max_extracted = -1
    service_request.extracted.clear()
    with pytest.raises(MaxExtractedExceeded):
        service_request.add_extracted(path, "name", "description")

    # Adding a file with a bunch of settings
    service_request.task.max_extracted = 1
    service_request.add_extracted(
        path, "name", "description", classification="TLP:AMBER",
        allow_dynamic_recursion=True, parent_relation="DYNAMIC"
    )
    # Note that classification is not enforced
    assert service_request.extracted == [
        {
            'allow_dynamic_recursion': True,
            'classification': 'TLP:C',
            'description': 'description',
            'is_section_image': False,
            'is_supplementary': False,
            'name': 'name',
            'parent_relation': 'DYNAMIC',
            'path': path,
            'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
        },
    ]


@pytest.mark.skipif(len(TESSERACT_LIST) < 1, reason="Requires tesseract-ocr apt package")
def test_add_image(service_request):
    image_path = os.path.join(
        os.path.dirname(__file__),
        "b32969aa664e3905c20f865cdd7b921f922678f5c3850c78e4c803fbc1757a8e")

    # Basic
    assert service_request.add_image(image_path, "image_name", "description of image") == {
        'img': {
            'description': 'description of image',
            'name': 'image_name',
            'sha256': '09bf99ab5431af13b701a06dc2b04520aea9fd346584fa2a034d6d4af0c57329'
        },
        'thumb': {
            'description': 'description of image (thumbnail)',
            'name': 'image_name.thumb',
            'sha256': '1af0e0d99845493b64cf402b3704170f17ecf15001714016e48f9d4854218901'
        }
    }

    for item in service_request.task.supplementary:
        item.pop("path")
    assert service_request.task.supplementary == [
        {
            'allow_dynamic_recursion': False,
            'classification': 'TLP:C',
            'description': 'description of image',
            'is_section_image': True,
            'is_supplementary': True,
            'name': 'image_name',
            'parent_relation': 'INFORMATION',
            'sha256': '09bf99ab5431af13b701a06dc2b04520aea9fd346584fa2a034d6d4af0c57329'
        },
        {
            'allow_dynamic_recursion': False,
            'classification': 'TLP:C',
            'description': 'description of image (thumbnail)',
            'is_section_image': True,
            'is_supplementary': True,
            'name': 'image_name.thumb',
            'parent_relation': 'INFORMATION',
            'sha256': '1af0e0d99845493b64cf402b3704170f17ecf15001714016e48f9d4854218901'
        },
    ]

    service_request.task.supplementary.clear()

    # Classification, OCR heuristic, OCR_IO, image with no password
    ocr_heuristic_id = 1
    _, path = tempfile.mkstemp()
    ocr_io = open(path, "w")
    data = service_request.add_image(image_path, "image_name", "description of image",
                                     "TLP:A", ocr_heuristic_id, ocr_io)
    assert data["img"] == {
        'description': 'description of image',
        'name': 'image_name',
        'sha256': '09bf99ab5431af13b701a06dc2b04520aea9fd346584fa2a034d6d4af0c57329'
    }
    assert data["thumb"] == {
        'description': 'description of image (thumbnail)',
        'name': 'image_name.thumb',
        'sha256': '1af0e0d99845493b64cf402b3704170f17ecf15001714016e48f9d4854218901'
    }
    assert data["ocr_section"].__dict__["section_body"].__dict__ == {
        '_config': {},
        '_data': {
            'ransomware': [
                "YOUR FILES HAVE BEEN ENCRYPTED AND YOU WON'T BE "
                'ABLE TO DECRYPT THEM.',
                'YOU CAN BUY DECRYPTION SOFTWARE FROM US, THIS '
                'SOFTWARE WILL ALLOW YOU TO RECOVER ALL OF YOUR DATA '
                'AND',
                'RANSOMWARE FROM YOUR COMPUTER. THE PRICE OF THE '
                'SOFTWARE IS $.2..%.. PAYMENT CAN BE MADE IN BITCOIN '
                'OR XMR.',
                'How 00! PAY, WHERE DO | GET BITCOIN OR XMR?',
                'YOURSELF TO FIND OUT HOW TO BUY BITCOIN OR XMR.',
                'PAYMENT INFORMATION: SEND $15, TO ONE OF OUR CRYPTO '
                'ADDRESSES, THEN SEND US EMAIL WITH PAYMENT',
                "CONFIRMATION AND YOU'LL GET THE DECRYPTION SOFTWARE IN EMAIL.",
                "BTC ADDRESS : bciqsht77cpgw7kv420r4secmu88g34wvn96dsyc5s",
            ]
        },
        '_format': 'KEY_VALUE'
    }

    heur_dict = get_heuristic_primitives(data["ocr_section"].__dict__["_heuristic"])

    assert heur_dict == {
        'heur_id': 1, 'score': 1200, 'attack_ids': ['T1005'],
        'signatures': {'ransomware_strings': 8},
        'frequency': 0, 'score_map': {}}

    assert service_request.temp_submission_data == {}

    service_request.task.supplementary.clear()

    # Classification, OCR heuristic, OCR_IO, image with password
    image_path = os.path.join(
        os.path.dirname(__file__),
        "4031ed8786439eee24b87f84901e38038a76b8c55e9d87dd5a7d88df2806c1cf")
    _, path = tempfile.mkstemp()
    ocr_io = open(path, "w")
    data = service_request.add_image(image_path, "image_name", "description of image",
                                     "TLP:A", ocr_heuristic_id, ocr_io)
    assert data["img"] == {
        'description': 'description of image',
        'name': 'image_name',
        'sha256': '9dac3e45d5a20626b5a96bcfb708160fb36690c41d07cad912289186726f9e57'
    }
    assert data["thumb"] == {
        'description': 'description of image (thumbnail)',
        'name': 'image_name.thumb',
        'sha256': '558358f966f17197a6a8dd479b99b6d5428f0848bc4c2b2511e6f34f5d2db645'
    }
    assert data["ocr_section"].__dict__["section_body"].__dict__ == {
        '_config': {},
        '_data': {'password': ['DOCUMENT PASSWORD: 975']},
        '_format': 'KEY_VALUE'
    }

    heur_dict = get_heuristic_primitives(data["ocr_section"].__dict__["_heuristic"])

    assert heur_dict == {
        'heur_id': 1, 'score': 250, 'attack_ids': ['T1005'],
        'signatures': {'password_strings': 1},
        'frequency': 0, 'score_map': {}}

    assert service_request.temp_submission_data == {'passwords': [' 975', '975', 'DOCUMENT', 'PASSWORD', 'PASSWORD:']}


def test_add_supplementary(service_request):
    # Bare minimum, empty file is ignored
    _, path = tempfile.mkstemp()
    service_request.add_supplementary(path, "name", "description")
    assert service_request.task.supplementary == []

    with open(path, "w") as f:
        f.write("test")

    # Now the file is not empty
    service_request.add_supplementary(path, "name", "description")
    assert service_request.task.supplementary == [
        {
            'allow_dynamic_recursion': False,
            'classification': 'TLP:C',
            'description': 'description',
            'is_section_image': False,
            'is_supplementary': True,
            'name': 'name',
            'parent_relation': 'INFORMATION',
            'path': path,
            'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
        },
    ]


def test_drop(service_request):
    service_request.drop()
    assert service_request.task.drop_file is True


def test_file_path(service_request):
    # File does not exist
    with pytest.raises(Exception):
        service_request.file_path

    # File exists now
    file_path = os.path.join(tempfile.gettempdir(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    with open(file_path, "w") as f:
        f.write("")
    assert service_request.file_path == file_path
    os.remove(file_path)


def test_file_contents(service_request):
    file_path = os.path.join(tempfile.gettempdir(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    with open(file_path, "w") as f:
        f.write("")

    assert service_request.file_contents == b""
    os.remove(file_path)


def test_get_param(service_request):
    # Submission parameter does not exist
    with pytest.raises(Exception):
        service_request.get_param("blah")

    # Submission parameter exists
    service_request.task.service_config = {"blah": "blah"}
    assert service_request.get_param("blah") == "blah"


def test_result_getter(service_request):
    assert isinstance(service_request.result, Result)


def test_result_setter(service_request):
    service_request.result = "blah"
    assert service_request.result == "blah"


def test_set_service_context(service_request):
    service_request.set_service_context("blah")
    assert service_request.task.service_context == "blah"


def test_temp_submission_data_getter(service_request):
    assert service_request.temp_submission_data == {}


def test_temp_submission_data_setter(service_request):
    service_request.temp_submission_data = {"blah": "blah"}
    assert service_request.temp_submission_data == {"blah": "blah"}
