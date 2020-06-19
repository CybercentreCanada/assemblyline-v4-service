import re
from copy import deepcopy
import os.path
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode, unquote

NUMBER_REGEX = re.compile("[0-9]*")
ALPHA_REGEX = re.compile("[a-zA-Z]*")
ALPHANUM_REGEX = re.compile("[a-zA-Z0-9]*")
BASE64_REGEX = re.compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


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
            uri_dict["path"] = os.path.split(uri_dict["path"])

        parsed_uris.append(uri_dict)

    # iterate through, comparing two parsed uris. if the percentage of similarity
    # is greater than x, then they are sufficiently similar and can have parts
    # replaced.

    # time for the smarts
    comparison_uris = deepcopy(parsed_uris)
    for parsed_uri in parsed_uris:
        for comparison_uri in comparison_uris:
            if parsed_uri == comparison_uri:
                continue
            equal_keys = 0
            max_tuple_len = 0
            len_keys = 0
            difference = {}
            # now go through each key, and check for equality
            for key in parsed_uri.keys():
                val = parsed_uri[key]
                comp_val = comparison_uri[key]

                # if equal, add to count of similar keys
                if type(val) == tuple:
                    val_len = len(val)
                    if val == comp_val:
                        equal_keys += val_len
                    else:
                        difference[key] = tuple()
                        comp_len = len(comp_val)
                        max_tuple_len = max(val_len, comp_len)
                        for item in range(max_tuple_len):
                            if item >= comp_len or item >= val_len:
                                # bail!
                                break
                            if val[item] == comp_val[item]:
                                equal_keys += 1
                            else:
                                difference[key] = difference[key] + (val[item],)
                                difference[key] = difference[key] + (comp_val[item],)

                elif type(val) == dict:
                    val_len = len(val)
                    if val == comp_val:
                        equal_keys += val_len
                    else:
                        difference[key] = dict()
                        comp_keys = list(comp_val.keys())
                        val_keys = list(val.keys())
                        all_keys = set(comp_keys + val_keys)
                        len_keys = len(all_keys)

                        for item in all_keys:
                            if val.get(item) and comp_val.get(item) and val[item] == comp_val[item]:
                                equal_keys += 1
                            else:
                                difference[key][item] = []
                                if val.get(item):
                                    difference[key][item].append(val[item])
                                if comp_val.get(item):
                                    difference[key][item].append(comp_val[item])
                else:  # Not dict or a tuple
                    if val == comp_val:
                        equal_keys += 1
                    else:
                        difference[key] = comp_val
            # now find percentage similar
            percentage_equal = equal_keys/(len(parsed_uri.keys())+max_tuple_len+len_keys)

            # if percentage equal is > some value (say 90), then we can say that
            # urls are similar enough to reduce
            if percentage_equal > 0.9:
                # So that we don't overwrite details
                comparison_uri_copy = deepcopy(comparison_uri)
                # somehow recognize where parameters are that match and replace them.
                for item in difference.keys():
                    if type(difference[item]) == dict:
                        for key in difference[item].keys():
                            placeholders = []
                            # since each of these items is a list of lists
                            for l in difference[item][key]:
                                # use regex to determine the parameter type
                                value = l[0]
                                if NUMBER_REGEX.fullmatch(value):
                                    placeholder = "${NUMBER}"
                                elif ALPHA_REGEX.fullmatch(value):
                                    placeholder = "${ALPHA}"
                                elif ALPHANUM_REGEX.fullmatch(value):
                                    placeholder = "${ALPHA_NUM}"
                                elif BASE64_REGEX.fullmatch(value):
                                    placeholder = "${BASE64}"
                                else:
                                    placeholder = "${UNKNOWN_TYPE}"
                                placeholders.append(placeholder)
                            if len(set(placeholders)) == 1:
                                # the same placeholder type is consistent with all values
                                # update the url_dict value
                                comparison_uri_copy[item][key] = list(set(placeholders))
                            else:
                                # the placeholder types vary
                                comparison_uri_copy[item][key] = ",".join(placeholders)
                    elif type(difference[item]) == tuple:
                        # TODO: implement this section when the path changes
                        pass
                    else:
                        # TODO: implement this if domains or anything else changes
                        pass

                # now it's time to rejoin the parts of the url
                # turn the path back into a string
                comparison_uri_copy["path"] = '/'.join(comparison_uri_copy["path"])
                # turn the query back into a query string
                # first, remove the list wrappers
                for item in comparison_uri_copy["query"].keys():
                    comparison_uri_copy["query"][item] = comparison_uri_copy["query"][item][0]
                comparison_uri_copy["query"] = unquote(urlencode(comparison_uri_copy["query"]))

                uri_tuple = (comparison_uri_copy["scheme"], comparison_uri_copy["netloc"],
                             comparison_uri_copy["path"], comparison_uri_copy["params"],
                             comparison_uri_copy["query"], comparison_uri_copy["fragment"])
                url = urlunparse(uri_tuple)
                reduced_uris.add(url)
    reduced_uris_list = list(reduced_uris)
    return reduced_uris_list


REDUCE_MAP = {
    "network.dynamic.uri": reduce_uri_tags,
    "network.static.uri": reduce_uri_tags,
    "network.dynamic.uri_path": reduce_uri_tags,
    "network.static.uri_path": reduce_uri_tags
}


if __name__ == "__main__":
    tags = {
        "network.static.uri": [
            # Those fail to find similarities but should
            "https://google.com?query=allo",
            "https://google.com?query=mon",
            "https://google.com?query=coco",
            # Those succeed
            "https://googlelicious.com/somepathother/?query=allo",
            "https://googlelicious.com/somepathother/?query=mon",
            "https://googlelicious.com/somepathother/?query=coco"
            # Those succeed
            "https://googlelicious.com/somepath/?rng=112431243",
            "https://googlelicious.com/somepath/?rng=124312431243",
            "https://googlelicious.com/somepath/?rng=22"
            # FAILED similarities are not returned but should
        ]
    }
    print({tag_type: REDUCE_MAP.get(tag_type, lambda x: x)(tag_values) for tag_type, tag_values in tags.items()})
