from __future__ import annotations

from typing import TextIO

import regex
from assemblyline_v4_service.common.helper import get_service_manifest
from assemblyline_v4_service.common.utils import PASSWORD_WORDS

# TODO: Would prefer this mapping to be dynamic from trusted sources (ie. import from library), but will copy-paste for now
OCR_INDICATORS_MAPPING: dict[str, list[str]] = {
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
        "personal code", "enter code", "your key", "unique key"
    ],
    'macros': [
        # https://github.com/cuckoosandbox/community/blob/17d57d46ccbca0327a8299cb93abba8604b74df7/modules/signatures/windows/office_enablecontent_ocr.py
        "enable macro",
        "enable content",
        "enable editing",
    ],
    'banned': [],
    'password': PASSWORD_WORDS
}


def ocr_detections(image_path: str, ocr_io: TextIO = None) -> dict[str, list[str]]:
    try:
        import pytesseract
        from PIL import Image
    except ImportError as exc:
        raise ImportError('In order to scan for OCR detections, ensure you have the following installed:\n'
                          'tesseract, pytesseract, and Pillow') from exc

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


def detections(ocr_output: str) -> dict[str, list[str]]:
    detection_output: dict[str, list[str]] = {}
    ocr_config: dict[str, list[str]] = {}
    try:
        # If running an AL service, grab OCR configuration from service manifest
        ocr_config = get_service_manifest().get('config', {}).get('ocr', {})
    except Exception:
        pass
    indicators = set(list(OCR_INDICATORS_MAPPING.keys()) + list(ocr_config.keys()))
    # Iterate over the different indicators and include lines of detection in response
    for indicator in indicators:
        list_of_terms = ocr_config.get(indicator, []) or OCR_INDICATORS_MAPPING.get(indicator, [])
        if not list_of_terms:
            # If no terms specified, move onto next indicator
            continue
        indicator_hits: set[str | None] = set()
        regex_exp = regex.compile(f"({')|('.join(list_of_terms).lower()})")
        list_of_strings: list[str] = []
        for line in ocr_output.split('\n'):
            search = regex_exp.search(line.lower())
            if search:
                indicator_hits = indicator_hits.union(set(search.groups()))
                list_of_strings.append(line)
        if None in indicator_hits:
            indicator_hits.remove(None)

        if list_of_strings:
            if len(indicator_hits) >= 2:
                # We consider the detection to be credible if there's more than a single indicator hit
                detection_output[indicator] = list_of_strings
            if indicator in ['banned', 'password']:
                # Except if we're dealing with banned/password, one hit is more than enough
                detection_output[indicator] = list_of_strings
    return detection_output
