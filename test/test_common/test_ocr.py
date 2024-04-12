import os
from test.test_common import TESSERACT_LIST

import pytest

from assemblyline_v4_service.common.ocr import ocr_detections, detections, update_ocr_config

@pytest.mark.skipif(len(TESSERACT_LIST) < 1, reason="Requires tesseract-ocr apt package")
def test_ocr_detections():
    update_ocr_config()
    file_path = os.path.join(os.path.dirname(__file__), "b32969aa664e3905c20f865cdd7b921f922678f5c3850c78e4c803fbc1757a8e")
    assert ocr_detections(file_path) == {
        'ransomware': [
            "YOUR FILES HAVE BEEN ENCRYPTED AND YOU WON'T BE ABLE TO "
            'DECRYPT THEM.',
            'YOU CAN BUY DECRYPTION SOFTWARE FROM US, THIS SOFTWARE WILL '
            'ALLOW YOU TO RECOVER ALL OF YOUR DATA AND',
            'RANSOMWARE FROM YOUR COMPUTER. THE PRICE OF THE SOFTWARE IS '
            '$.2..%.. PAYMENT CAN BE MADE IN BITCOIN OR XMR.',
            'How 00! PAY, WHERE DO | GET BITCOIN OR XMR?',
            'YOURSELF TO FIND OUT HOW TO BUY BITCOIN OR XMR.',
            'PAYMENT INFORMATION: SEND $15, TO ONE OF OUR CRYPTO '
            'ADDRESSES, THEN SEND US EMAIL WITH PAYMENT',
            "CONFIRMATION AND YOU'LL GET THE DECRYPTION SOFTWARE IN EMAIL.",
            "BTC ADDRESS : bciqsht77cpgw7kv420r4secmu88g34wvn96dsyc5s",
        ],
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
    assert detections("blah\nrecover them\nblah\nencrypt") == {"ransomware": ["recover them", "encrypt"]}
