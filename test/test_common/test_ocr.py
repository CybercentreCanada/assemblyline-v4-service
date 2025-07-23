import os

import pytest
from assemblyline_v4_service.common.ocr import (
    detections,
    ocr_detections,
    update_ocr_config,
)

from test.test_common import TESSERACT_LIST


@pytest.mark.skipif(
    len(TESSERACT_LIST) < 1, reason="Requires tesseract-ocr apt package"
)
def test_ocr_detections():
    update_ocr_config()
    file_path = os.path.join(
        os.path.dirname(__file__),
        "094177fc6c4642f12fbf6dce18f272227ace95576ff1765384902d2abebf09bf",
    )
    assert ocr_detections(file_path) == {
        "ransomware": [
            "YOU CAN BUY DECRYPTION SOFTWARE FROM US, THIS SOFTWARE WILL ALLOW YOU TO RECOVER ALL OF YOUR DATA AND",
            "CONFIRMATION AND YOU'LL GET THE DECRYPTION KEY IN EMAIL.",
        ]
    }


def test_detections():
    update_ocr_config()

    # No detection
    assert detections("blah") == {}

    # Containing a banned string
    assert detections("blah\nrecover them\ndonotscanme") == {"banned": ["donotscanme"]}

    # Containing a single ransomware string
    assert detections("blah\nrecover them\nblah") == {}

    # Containing two ransomware strings
    assert detections("blah\nrecover data\nblah\nencrypted data") == {
        "ransomware": ["recover data", "encrypted data"]
    }
