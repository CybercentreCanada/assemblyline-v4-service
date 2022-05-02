from re import IGNORECASE, match
from typing import Dict, List


def is_tag_safelisted(
        value: str, tags: List[str],
        safelist: Dict[str, Dict[str, List[str]]],
        substring: bool = False) -> bool:
    """
    This method determines if a given value has any safelisted components.
    :param value: The value to be checked if it has been safelisted
    :param tags: The tags which will be used for grabbing specific values from the safelist
    :param safelist: The safelist containing matches and regexs. The product of a service using self.get_api_interface().get_safelist().
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
