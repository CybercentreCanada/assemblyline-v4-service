import re
from copy import deepcopy
import os.path
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode, unquote

NUMBER_REGEX = re.compile("[0-9]*")
ALPHA_REGEX = re.compile("[a-zA-Z]*")
ALPHANUM_REGEX = re.compile("[a-zA-Z0-9]*")
BASE64_REGEX = re.compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
DO_NOT_REDUCE = ["netloc", "hostname"]


def reduce_uri_tags(uris=None) -> []:
    """
    The purpose of this helper function is to reduce the amount of unique uris to be tagged.
    ex. If a sample makes a hundred network calls to four unqiue domains, with only one parameter
    changing in the HTTP request each time, this should be synthesized to four uris to
    be tagged, but with a placeholder for the parameter(s) that changes in each callout.
    """
    if uris is None:
        uris = []

    parsed_uris = []
    reduced_uris = set()
    for uri in uris:
        parsed_uri = urlparse(uri)
        # Match items we care about into a nice dictionary
        uri_dict = {
            "scheme": parsed_uri.scheme,      # scheme param
            "netloc": parsed_uri.netloc,      # ""
            "path": parsed_uri.path,          # ""
            "params": parsed_uri.params,      # ""
            "query": parsed_uri.query,        # ""
            "fragment": parsed_uri.fragment,  # ""
            "username": parsed_uri.username,  # None
            "password": parsed_uri.password,  # None
            "hostname": parsed_uri.hostname,  # None
            "port": parsed_uri.port           # None
        }

        # We need to parse a couple of the returned params from urlparse more in-depth
        if uri_dict["query"] != "":
            # note that values of keys in dict will be in lists of length 1, which we don't want
            uri_dict["query"] = parse_qs(uri_dict["query"])
        if uri_dict["path"] != "":
            # converting tuple to list
            uri_dict["path"] = list(os.path.split(uri_dict["path"]))
            # removing lone slashes
            uri_dict["path"] = [not_slash for not_slash in uri_dict["path"] if not_slash != "/"]

        parsed_uris.append(uri_dict)

    # iterate through, comparing two parsed uris. if the percentage of similarity
    # is greater than x, then they are sufficiently similar and can have parts
    # replaced.

    # time for the smarts
    comparison_uris = deepcopy(parsed_uris)
    for parsed_uri in parsed_uris:
        # this flag will be used to check if this uri matches any other uri ever
        totally_unique = True
        for comparison_uri in comparison_uris:
            if parsed_uri == comparison_uri:
                continue
            equal_keys = 0
            total_list_len = 0
            total_dict_len = 0
            difference = {}
            # now go through each key, and check for equality
            for key in parsed_uri.keys():
                val = parsed_uri[key]
                comp_val = comparison_uri[key]

                # if equal, add to count of similar keys
                if type(val) == list:
                    val_len = len(val)
                    if val == comp_val:
                        equal_keys += val_len
                    else:
                        difference[key] = dict()
                        comp_len = len(comp_val)
                        max_list_len = max(val_len, comp_len)
                        for item in range(max_list_len):
                            if item >= comp_len or item >= val_len:
                                # bail!
                                break
                            if val[item] == comp_val[item]:
                                equal_keys += 1
                            else:
                                difference[key][item] = []
                                difference[key][item].append(val[item])
                                difference[key][item].append(comp_val[item])
                        total_list_len += val_len

                elif type(val) == dict:
                    val_len = len(val)
                    if val == comp_val:
                        equal_keys += val_len
                    else:
                        difference[key] = dict()
                        if comp_val != "":
                            comp_keys = list(comp_val.keys())
                            val_keys = list(val.keys())
                            all_keys = set(comp_keys + val_keys)
                            val_len = len(all_keys)

                            for item in all_keys:
                                if val.get(item) and comp_val.get(item) and val[item] == comp_val[item]:
                                    equal_keys += 1
                                else:
                                    difference[key][item] = []
                                    if val.get(item):
                                        difference[key][item].append(val[item])
                                    if comp_val.get(item):
                                        difference[key][item].append(comp_val[item])
                        total_dict_len += val_len
                else:  # Not dict or a list
                    if val == comp_val:
                        equal_keys += 1
                    else:
                        difference[key] = []
                        difference[key].append(val)
                        difference[key].append(comp_val)
            # now find percentage similar
            if total_dict_len > 1 and total_list_len > 1:
                percentage_equal = equal_keys / (len(parsed_uri.keys()) - 2 + total_list_len + total_dict_len)
            elif total_dict_len > 1 or total_list_len > 1:
                percentage_equal = equal_keys / (len(parsed_uri.keys()) - 1 + total_list_len + total_dict_len)
            else:
                percentage_equal = equal_keys / (len(parsed_uri.keys()) + total_list_len + total_dict_len)

            # if percentage equal is > some value (say 90), then we can say that
            # urls are similar enough to reduce
            if percentage_equal >= 0.80:
                # So that we don't overwrite details
                comparison_uri_copy = deepcopy(comparison_uri)
                # somehow recognize where parameters are that match and replace them.
                for item in difference.keys():
                    # We don't want to replace the following:
                    if item in DO_NOT_REDUCE:
                        continue

                    val = difference[item]
                    if item == "query":
                        for key in val.keys():
                            placeholders = []
                            # since each of these items is a list of lists
                            for l in val[key]:
                                # use regex to determine the parameter type
                                value = l[0]
                                placeholder = _get_placeholder(value)
                                placeholders.append(placeholder)
                            if len(set(placeholders)) == 1:
                                # the same placeholder type is consistent with all values
                                # update the url_dict value
                                comparison_uri_copy[item][key] = list(set(placeholders))
                            else:
                                # the placeholder types vary
                                comparison_uri_copy[item][key] = ",".join(placeholders)
                    elif item == "path":
                        placeholders = {}
                        for key in val.keys():
                            placeholders[key] = []
                            for list_item in val[key]:
                                # if / exists, pop the rest out
                                if list_item != "/" and list_item[0] == "/":
                                    # use regex to determine the parameter type
                                    placeholder = _get_placeholder(list_item[1:])
                                    placeholders[key].append("/"+placeholder)
                                else:
                                    placeholder = _get_placeholder(list_item)
                                    placeholders[key].append(placeholder)
                        for key in placeholders.keys():
                            if len(set(placeholders[key])) == 1:
                                # the same placeholder type is consistent with all values
                                # update the comparison_uri_copy value
                                comparison_uri_copy[item][key] = list(set(placeholders[key]))[0]
                            else:
                                # the placeholder types vary
                                comparison_uri_copy[item][key] = ",".join(set(placeholders[key]))
                    else:
                        comparison_uri_copy[item] = _get_placeholder(val)

                # now it's time to rejoin the parts of the url
                reduced_uris.add(_turn_back_into_uri(comparison_uri_copy))
                totally_unique = False

        # Congratulations, you are one in a million
        if totally_unique:
            reduced_uris.add(_turn_back_into_uri(parsed_uri))
    reduced_uris_list = list(reduced_uris)
    # recursive_list = reduce_uri_tags(reduced_uris_list)
    # if len(recursive_list) < len(reduced_uris_list):
    #     return reduced_uris_list
    # elif
    # if reduce_uri_tags(reduced_uris_list))
    return reduced_uris_list


def _turn_back_into_uri(uri_parts: dict) -> str:
    # turn the path back into a string
    uri_parts["path"] = '/'.join(uri_parts["path"])
    # turn the query back into a query string
    # first, remove the list wrappers
    if uri_parts["query"] != "":
        for item in uri_parts["query"].keys():
            uri_parts["query"][item] = uri_parts["query"][item][0]
    uri_parts["query"] = unquote(urlencode(uri_parts["query"]))

    uri_tuple = (uri_parts["scheme"], uri_parts["netloc"],
                 uri_parts["path"], uri_parts["params"],
                 uri_parts["query"], uri_parts["fragment"])
    real_url = urlunparse(uri_tuple)
    return real_url


def _get_placeholder(val: str) -> str:
    if not val:
        return "${UNKNOWN_TYPE}"

    if NUMBER_REGEX.fullmatch(val):
        placeholder = "${NUMBER}"
    elif ALPHA_REGEX.fullmatch(val):
        placeholder = "${ALPHA}"
    # Note that BASE64 Regex must happen before ALPHANUM regex or else ALPHANUM will hit on BASE64
    elif BASE64_REGEX.fullmatch(val):
        placeholder = "${BASE64}"
    elif ALPHANUM_REGEX.fullmatch(val):
        placeholder = "${ALPHA_NUM}"
    else:
        placeholder = "${UNKNOWN_TYPE}"
    return placeholder


REDUCE_MAP = {
    "network.dynamic.uri": reduce_uri_tags,
    "network.static.uri": reduce_uri_tags,
    "network.dynamic.uri_path": reduce_uri_tags,
    "network.static.uri_path": reduce_uri_tags
}
