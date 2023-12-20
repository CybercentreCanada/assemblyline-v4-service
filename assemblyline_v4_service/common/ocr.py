from __future__ import annotations

from typing import Dict, List, TextIO

from assemblyline_v4_service.common.helper import get_service_manifest
from assemblyline_v4_service.common.utils import PASSWORD_WORDS

# TODO: Would prefer this mapping to be dynamic from trusted sources (ie. import from library), but will copy-paste for now
OCR_INDICATORS_TERMS: dict[str, list[str]] = {
    'ransomware': [
        # https://github.com/cuckoosandbox/community/blob/master/modules/signatures/windows/ransomware_message.py
        "your files", "your data", "your documents", "restore files",
        "restore data", "restore the files", "restore the data", "recover files",
        "recover data", "recover the files", "recover the data", "has been locked",
        "pay fine", "pay a fine", "pay the fine", "decrypt", "encrypt",
        "recover files", "recover data", "recover them", "recover your",
        "recover personal", "bitcoin", "secret server", "secret internet server",
        "install tor", "download tor", "tor browser", "tor gateway",
        "tor-browser", "tor-gateway", "torbrowser", "torgateway", "torproject.org",
        "ransom", "bootkit", "rootkit", "payment", "victim", "AES128", "AES256",
        "AES 128", "AES 256", "AES-128", "AES-256", "RSA1024", "RSA2048",
        "RSA4096", "RSA 1024", "RSA 2048", "RSA 4096", "RSA-1024", "RSA-2048",
        "RSA-4096", "private key", "personal key", "your code", "private code",
        "personal code", "enter code", "your key", "unique key",
        # https://github.com/CAPESandbox/community/blob/815e21980f4b234cf84e78749447f262af2beef9/modules/signatures/office_macro.py
        "bank account",
        # https://github.com/CAPESandbox/community/blob/815e21980f4b234cf84e78749447f262af2beef9/modules/signatures/ransomware_message.py
        "Attention!", "BTC", "HardwareID", "bit coin", "decrypter", "decryptor",
        "device ID", "encrypted", "encryption ID", "ethereum", "get back my",
        "get back your", "localbitcoins", "military grade encryption", "personal ID",
        "personal identification code", "personal identifier",
        "recover datarecover the files", "recover my", "restore system",
        "restore the system", "unique ID", "wallet address", "what happend",
        "what happened", "your database", "your network",
        # Other
        "ether", "litecoin", "coin",
    ],
    'macros': [
        # https://github.com/cuckoosandbox/community/blob/17d57d46ccbca0327a8299cb93abba8604b74df7/modules/signatures/windows/office_enablecontent_ocr.py
        "enable macro",
        "enable content",
        "enable editing",
        # https://github.com/CAPESandbox/community/blob/815e21980f4b234cf84e78749447f262af2beef9/modules/signatures/office_macro.py
        "tools > macro",
        "macros must be enabled",
        # Other
        "protected documents",
    ],
    'banned': [],
    'password': PASSWORD_WORDS,
    'phishing': [
        # https://github.com/CAPESandbox/community/blob/815e21980f4b234cf84e78749447f262af2beef9/modules/signatures/js_phish.py
        "debug malware error",
        "contact microsoft certified",
        "non bootable situation",
        "windows system alert",
        "your browser has been infected",
        "your paypal id or password was entered incorrectly",
        "your customer number is made up of your date of birth",
        'Invalid Card Number',
        'Invalid Card Verification Number',
        # Other
        "online banking", "security challenge", "forgot password", "card number", "mobile banking", "paypal account",
        "forgot email", "banking security", "remember password", "verify your identity", "secure login",
        "enter security", "create account", "confirm your", "enter document", "document security",
    ]
}

# The minimum number of indicator hits to avoid FP detections
OCR_INDICATORS_THRESHOLD: Dict[str, int] = {"ransomware": 2, "macros": 2, "banned": 1, "password": 1}

try:
    # Retrieve service-configured OCR settings on module load
    ocr_config: Dict = get_service_manifest().get("config", {}).get("ocr", {})
    indicators = set(list(OCR_INDICATORS_TERMS.keys()) + list(ocr_config.keys()))
    for i in indicators:
        # Backwards compatibility: Check how the OCR configuration is formatted
        indicator_config = ocr_config.get(i)
        indicator_terms = []
        indicator_threshold = 1
        if not indicator_config:
            # Empty block/no override provided by service
            pass
        elif isinstance(indicator_config, list):
            # Legacy support (before configurable indicator thresholds)
            indicator_terms = indicator_config
            pass
        elif isinstance(indicator_config, dict):
            # Set indicator threshold before variable overwrite with terms list
            indicator_terms = indicator_config.get('terms', [])
            indicator_threshold = indicator_config.get('threshold', 1)
        OCR_INDICATORS_TERMS[i] = indicator_terms or OCR_INDICATORS_TERMS.get(i, [])
        OCR_INDICATORS_THRESHOLD[i] = indicator_threshold or OCR_INDICATORS_THRESHOLD.get(i, 1)

except Exception:
    pass


def ocr_detections(image_path: str, ocr_io: TextIO = None) -> Dict[str, List[str]]:
    try:
        import pytesseract
        from PIL import Image
    except ImportError as exc:
        raise ImportError(
            "In order to use this method to scan for OCR detections, "
            "ensure you have the following installed in your service:\n"
            "tesseract-ocr, pytesseract, and Pillow.\n"
            'You can do this via "apt-get install -y tesseract-ocr" and "pip install Pillow pytesseract"'
        ) from exc

    # Use OCR library to extract strings from an image file
    ocr_output = ""

    try:
        ocr_output = pytesseract.image_to_string(
            Image.open(image_path), timeout=15
        )  # Stop OCR after 15 seconds
    except (TypeError, RuntimeError):
        # Image given isn't supported therefore no OCR output can be given with tesseract
        return {}

    if ocr_io:
        ocr_io.flush()
        ocr_io.write(ocr_output)
        ocr_io.flush()

    return detections(ocr_output)


def detections(ocr_output: str) -> Dict[str, List[str]]:
    indicators = list(OCR_INDICATORS_TERMS.keys())
    ocr_config = {}
    try:
        # Retrieve service-configured OCR settings on module load
        ocr_config: Dict = get_service_manifest().get("config", {}).get("ocr", {})
        indicators = set(list(OCR_INDICATORS_TERMS.keys()) + list(ocr_config.keys()))
    except Exception:
        pass

    detection_output: Dict[str, List[str]] = {}
    # Iterate over the different indicators and include lines of detection in response
    for indicator in indicators:
        # Backwards compatibility: Check how the OCR configuration is formatted
        indicator_config = ocr_config.get(indicator)
        terms = OCR_INDICATORS_TERMS.get(indicator, [])
        hit_threshold = OCR_INDICATORS_THRESHOLD.get(indicator, 1)
        if not indicator_config:
            # Empty block/no override provided by service
            pass
        elif isinstance(indicator_config, list):
            # Legacy support (before configurable indicator thresholds)
            terms = indicator_config
            pass
        elif isinstance(indicator_config, dict):
            # Set indicator threshold before variable overwrite with terms list
            terms = indicator_config.get('terms', [])
            hit_threshold = indicator_config.get('threshold', 1)

        # Perform a pre-check to see if the terms even exist in the OCR text
        if not any([t.lower() in ocr_output.lower() for t in terms]):
            continue

        # Keep a track of the hits and the lines corresponding with term hits
        indicator_hits: int = 0
        list_of_strings: List[str] = []
        for line in ocr_output.split("\n"):
            for t in terms:
                term_count = line.lower().count(t.lower())
                if term_count:
                    indicator_hits += term_count
                    if line not in list_of_strings:
                        list_of_strings.append(line)

        if list_of_strings and indicator_hits >= hit_threshold:
            # If we were to find hits and those hits are above the required threshold, then add them to output
            detection_output[indicator] = list_of_strings
    return detection_output
