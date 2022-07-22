import json
import time
from assemblyline.common import forge
from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection
from assemblyline_v4_service.common.virustotal.common.processing import format_time_from_epoch

Classification = forge.get_classification()


def v3(doc: dict):
    attributes = doc.get('attributes', {})

    # Scans
    hit_list = list()
    und_list = list()
    sig_list = list()
    for av, props in sorted(attributes['last_analysis_results'].items()):
        if props['category'] == "malicious":
            hit_list.append(av)
            sig_list.append(f"{av}.{props['result']}")
        elif props['category'] == "undetected":
            und_list.append(av)

    # Submission meta
    categories = [v for _, v in attributes.get("categories", {}).items()]
    body_dict = {
        "Categories": ", ".join(categories),
        "Last Modification Date": format_time_from_epoch(attributes['last_modification_date']),
        "Permalink": f"https://www.virustotal.com/gui/{doc['type']}/{doc['id']}",
        "Reputation": attributes['reputation']
    }
    if hit_list:
        body_dict['Detected By'] = ", ".join(hit_list)
    elif und_list:
        body_dict['Undetected By'] = ", ".join(und_list)

    term = doc['id']
    main_section = ResultSection(term)

    # Submission meta
    ResultSection("VirusTotal Statistics", body=json.dumps(body_dict), body_format=BODY_FORMAT.KEY_VALUE,
                  parent=main_section, classification=Classification.UNRESTRICTED)

    # TODO:Have analysis for IP/Domains
    if sig_list:
        main_section.set_heuristic(2)
        [main_section.heuristic.add_signature_id(sig) for sig in sig_list]

    # Tags
    main_section.add_tag(f"network.static.{doc['type'].split('_')[0].lower()}", term)
    return main_section


def attach_ontology(ontology_helper: None, doc: dict):
    return
