from re import compile, IGNORECASE, match, search
from typing import Dict, List
from urllib.parse import urlparse

from assemblyline.odm.base import DOMAIN_REGEX, IP_REGEX

URL_REGEX = compile(
    r"(?:(?:(?:[A-Za-z]*:)?//)?(?:\S+(?::\S*)?@)?(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[A-Za-z0-9\u00a1-\uffff][A-Za-z0-9\u00a1-\uffff_-]{0,62})"
    r"?[A-Za-z0-9\u00a1-\uffff]\.)+(?:xn--)?(?:[A-Za-z0-9\u00a1-\uffff]{2,}\.?))(?::\d{2,5})?)(?:[/?#][^\s,\\\\]*)?")


def is_tag_safelisted(
        value: str, tags: List[str],
        safelist: Dict[str, Dict[str, List[str]]],
        substring: bool = False) -> bool:
    """
    This method determines if a given value has any safelisted components.
    :param value: The value to be checked if it has been safelisted
    :param tags: The tags which will be used for grabbing specific values from the safelist
    :param safelist: The safelist containing matches and regexs. The
                     product of a service using self.get_api_interface().get_safelist().
    :param substring: A flag that indicates if we should check if the value is contained within the match
    :return: A boolean indicating if the value has been safelisted
    """
    if not value or not tags or not safelist:
        return False

    if not any(key in safelist for key in ["match", "regex"]):
        return False

    safelist_matches = safelist.get("match", {})
    safelist_regexes = safelist.get("regex", {})

    for tag in tags:
        if tag in safelist_matches:
            for safelist_match in safelist_matches[tag]:
                if value.lower() == safelist_match.lower():
                    return True
                elif substring and safelist_match.lower() in value.lower():
                    return True

        if tag in safelist_regexes:
            for safelist_regex in safelist_regexes[tag]:
                if match(safelist_regex, value, IGNORECASE):
                    return True

    return False


def contains_safelisted_value(val: str, safelist: Dict[str, Dict[str, List[str]]]) -> bool:
    """
    This method checks if a given value is part of a safelist
    :param val: The given value
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: A boolean representing if the given value is part of a safelist
    """
    if not val or not isinstance(val, str):
        return False
    ip = search(IP_REGEX, val)
    url = search(URL_REGEX, val)
    domain = search(DOMAIN_REGEX, val)
    if ip is not None:
        ip = ip.group()
        return is_tag_safelisted(ip, ["network.dynamic.ip"], safelist)
    elif domain is not None:
        domain = domain.group()
        return is_tag_safelisted(domain, ["network.dynamic.domain"], safelist)
    elif url is not None:
        url_pieces = urlparse(url.group())
        domain = url_pieces.netloc
        return is_tag_safelisted(domain, ["network.dynamic.domain"], safelist)
    return False
