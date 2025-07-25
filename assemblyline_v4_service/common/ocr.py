from __future__ import annotations

from typing import Any, Dict, List, TextIO, Union

from assemblyline_v4_service.common.helper import get_service_manifest
from assemblyline_v4_service.common.utils import PASSWORD_WORDS

# The terms related to each indicator category
OCR_INDICATORS_TERMS: dict[str, list[str]] = {
    "ransomware": [
         "tor browser",
         "torproject org",
         "www torproject",
         "www torproject org",
         "https www torproject",
         "https www torproject org",
         "install tor",
         "install tor browser",
         "tor browser https",
         "files encrypted",
         "download install tor",
         "download install tor browser",
         "browser https www torproject",
         "decrypt files",
         "tor browser https www",
         "private key",
         "id snip",
         "download tor",
         "onion http",
         "install tor browser https",
         "https torproject",
         "https torproject org",
         "onion snip",
         "torproject org download",
         "www torproject org download",
         "download tor browser",
         "restore files",
         "recover files",
         "decryption software",
         "pay ransom",
         "decryption tool",
         "data loss",
         "tor browser open",
         "data encrypted",
         "important files",
         "data stolen",
         "damage files",
         "decrypt file",
         "tor browser http",
         "leaked data",
         "recover data",
         "tor browser site",
         "using tor",
         "decrypt data",
         "decrypt file free",
         "install tor browser site",
         "key snip",
         "tor browser site https",
         "using tor browser",
         "decryption key",
         "onion login",
         "password snip",
         "site https torproject",
         "site https torproject org",
         "tor browser download",
         "browser https torproject",
         "browser https torproject org",
         "browser site https torproject",
         "permanent data",
         "permanent data loss",
         "tor browser https torproject",
         "torproject org open",
         "contact soon possible",
         "delete data",
         "don try",
         "encrypted data",
         "https ibb",
         "https ibb snip",
         "ibb snip",
         "onionmail org",
    ],
    "macros": [
        # https://github.com/cuckoosandbox/community/blob/17d57d46ccbca0327a8299cb93abba8604b74df7/modules/signatures/windows/office_enablecontent_ocr.py
        "enable content",
        "enable editing",
        "enable macro",
        # https://github.com/CAPESandbox/community/blob/815e21980f4b234cf84e78749447f262af2beef9/modules/signatures/office_macro.py
        "macros must be enabled",
        "tools > macro",
        # Other
        "protected documents",
    ],
    "banned": [],
    "password": PASSWORD_WORDS,
    "phishing": [
        # https://github.com/CAPESandbox/community/blob/815e21980f4b234cf84e78749447f262af2beef9/modules/signatures/js_phish.py
        "Invalid Card Number",
        "Invalid Card Verification Number",
        "contact microsoft certified",
        "debug malware error",
        "non bootable situation",
        "windows system alert",
        "your browser has been infected",
        "your customer number is made up of your date of birth",
        "your paypal id or password was entered incorrectly",
        # Other
        "banking security",
        "card number",
        "click here to view",
        "confirm your",
        "create account",
        "document security",
        "enter document",
        "enter security",
        "forgot email",
        "forgot password",
        "mobile banking",
        "online banking",
        "paypal account",
        "remember password",
        "secure login",
        "security challenge",
        "verify your identity",
    ],
}

# The minimum number of indicator hits to avoid FP detections
OCR_INDICATORS_THRESHOLD: Dict[str, int] = {"ransomware": 2, "macros": 2, "banned": 1, "password": 1}

def update_ocr_config(ocr_config: Dict[str, Union[List[str], Dict[str, Any]]] = None):
    global OCR_INDICATORS_TERMS
    global OCR_INDICATORS_THRESHOLD
    if not ocr_config:
        try:
            # Retrieve service-configured OCR settings on module load (primary used in testing)
            ocr_config: Dict = get_service_manifest().get("config", {}).get("ocr", {})
        except Exception:
            # No configuration updates provided
            return

    indicators = set(list(OCR_INDICATORS_TERMS.keys()) + list(ocr_config.keys()))
    # Iterate over the different indicators and include lines of detection in response
    for indicator in indicators:
        indicator_config = ocr_config.get(indicator)
        terms = OCR_INDICATORS_TERMS.get(indicator, [])
        hit_threshold = OCR_INDICATORS_THRESHOLD.get(indicator, 1)
        # Backwards compatibility: Check how the OCR configuration is formatted
        if not indicator_config:
            # Empty block/no override provided by service
            pass
        elif isinstance(indicator_config, list):
            # Legacy support (before configurable indicator thresholds)
            terms = indicator_config
        elif isinstance(indicator_config, dict):
            # Either you're exclusively overwriting the terms list or you're selectively including/excluding terms
            if indicator_config.get("terms"):
                # Overwrite terms list with service configuration
                terms = indicator_config["terms"]
            else:
                included_terms = set(indicator_config.get("include", []))
                excluded_terms = set(indicator_config.get("exclude", []))
                # Compute the new terms list for indicator type
                terms = list(set(terms).union(included_terms) - excluded_terms)

            # Set the indicator hit threshold
            hit_threshold = indicator_config.get("threshold", 1)

        # Overwrite key-value in respective constants
        OCR_INDICATORS_TERMS[indicator] = terms
        OCR_INDICATORS_THRESHOLD[indicator] = hit_threshold


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
        ocr_output = pytesseract.image_to_string(Image.open(image_path), timeout=15)  # Stop OCR after 15 seconds
    except (TypeError, RuntimeError):
        # Image given isn't supported therefore no OCR output can be given with tesseract
        return {}

    if ocr_io:
        ocr_io.flush()
        ocr_io.write(ocr_output)
        ocr_io.flush()

    return detections(ocr_output)


def detections(ocr_output: str) -> Dict[str, List[str]]:
    detection_output: Dict[str, List[str]] = {}
    for indicator, terms in OCR_INDICATORS_TERMS.items():
        hit_threshold = OCR_INDICATORS_THRESHOLD[indicator]
        # Perform a pre-check to see if the terms even exist in the OCR text
        if not any([t.lower() in ocr_output.lower() for t in terms]):
            continue

        # Keep a track of the hits and the lines corresponding with term hits
        indicator_hits: set = set()
        list_of_strings: List[str] = []
        for line in ocr_output.split("\n"):
            for t in terms:
                term_count = line.lower().count(t.lower())
                if term_count:
                    indicator_hits.add(t)
                    if line not in list_of_strings:
                        list_of_strings.append(line)

        if list_of_strings and len(indicator_hits) >= hit_threshold:
            # If we were to find hits and those hits are above the required threshold, then add them to output
            detection_output[indicator] = list_of_strings
    return detection_output
