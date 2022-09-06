from re import match, search
from typing import Any, Dict, List, Optional, Union

from assemblyline.common.net import is_valid_domain, is_valid_ip
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.base import DOMAIN_ONLY_REGEX, DOMAIN_REGEX, FULL_URI, IP_REGEX, URI_PATH
from assemblyline_v4_service.common.result import ResultSection
from assemblyline_v4_service.common.safelist_helper import is_tag_safelisted

FALSE_POSITIVE_DOMAINS_FOUND_IN_PATHS = ["microsoft.net", "wscript.shell"]
COMMON_FILE_EXTENSIONS = [
    'bat', 'bin', 'cpl', 'dll', 'doc', 'docm', 'docx', 'dotm', 'elf', 'eml', 'exe', 'hta', 'htm', 'html',
    'hwp', 'jar', 'js', 'lnk', 'mht', 'msg', 'msi', 'pdf', 'potm', 'potx', 'pps', 'ppsm', 'ppsx', 'ppt',
    'pptm', 'pptx', 'ps1', 'pub', 'py', 'pyc', 'rar', 'rtf', 'sh', 'swf', 'vbs', 'wsf', 'xls', 'xlsm', 'xlsx'
]


def add_tag(
    result_section: ResultSection,
    tag: str, value: Union[Any, List[Any]],
    safelist: Dict[str, Dict[str, List[str]]] = None
) -> bool:
    """
    This method adds the value(s) as a tag to the ResultSection. Can take a list of values or a single value.
    :param result_section: The ResultSection that the tag will be added to
    :param tag: The tag type that the value will be tagged under
    :param value: The value, a single item or a list, that will be tagged under the tag type
    :param safelist: The safelist containing matches and regexs. The product of a
                     service using self.get_api_interface().get_safelist().
    :return: Tag was successfully added
    """
    if safelist is None:
        safelist = {}

    tags_were_added = False
    if not value:
        return tags_were_added

    if type(value) == list:
        for item in value:
            # If one tag is added, then return True
            tags_were_added = _validate_tag(result_section, tag, item, safelist) or tags_were_added
    else:
        tags_were_added = _validate_tag(result_section, tag, value, safelist)
    return tags_were_added


def _get_regex_for_tag(tag: str) -> str:
    """
    This method returns a regular expression used for validating a certain tag type
    :param tag: The type of tag
    :return: The relevant regular expression
    """
    reg_to_match: Optional[str] = None
    if "domain" in tag:
        reg_to_match = DOMAIN_ONLY_REGEX
    elif "uri_path" in tag:
        reg_to_match = URI_PATH
    elif "uri" in tag:
        reg_to_match = FULL_URI
    elif "ip" in tag:
        reg_to_match = IP_REGEX
    return reg_to_match


def _validate_tag(
    result_section: ResultSection,
    tag: str,
    value: Any,
    safelist: Dict[str, Dict[str, List[str]]] = None
) -> bool:
    """
    This method validates the value relative to the tag type before adding the value as a tag to the ResultSection.
    :param result_section: The ResultSection that the tag will be added to
    :param tag: The tag type that the value will be tagged under
    :param value: The item that will be tagged under the tag type
    :param safelist: The safelist containing matches and regexs. The product of a
                     service using self.get_api_interface().get_safelist().
    :return: Tag was successfully added
    """
    if safelist is None:
        safelist = {}

    regex = _get_regex_for_tag(tag)
    if regex and not match(regex, value):
        return False

    if "ip" in tag and not is_valid_ip(value):
        return False

    if "domain" in tag:
        if not is_valid_domain(value):
            return False
        elif value in FALSE_POSITIVE_DOMAINS_FOUND_IN_PATHS:
            return False
        elif isinstance(value, str) and value.split(".")[-1] in COMMON_FILE_EXTENSIONS:
            return False

    if is_tag_safelisted(value, [tag], safelist):
        return False

    # if "uri" is in the tag, let's try to extract its domain/ip and tag it.
    if "uri_path" not in tag and "uri" in tag:
        # First try to get the domain
        valid_domain = False
        domain = search(DOMAIN_REGEX, value)
        if domain:
            domain = domain.group()
            valid_domain = _validate_tag(result_section, "network.dynamic.domain", domain, safelist)
        # Then try to get the IP
        valid_ip = False
        ip = search(IP_REGEX, value)
        if ip:
            ip = ip.group()
            valid_ip = _validate_tag(result_section, "network.dynamic.ip", ip, safelist)

        if value not in [domain, ip] and (valid_domain or valid_ip):
            result_section.add_tag(tag, safe_str(value))
        else:
            return False
    else:
        result_section.add_tag(tag, safe_str(value))

    return True
