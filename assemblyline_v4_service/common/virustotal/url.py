import json
from assemblyline.common import forge
from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from assemblyline_v4_service.common.virustotal.common.processing import format_time_from_epoch


Classification = forge.get_classification()


def v3(doc: dict):
    attributes = doc.get('attributes', {})
    context = doc.get('context_attributes', {})

    submitter = context.get('submitter', None)
    if submitter:
        submitter = ResultSection("Submitter details", body=json.dumps(submitter),
                                  body_format=BODY_FORMAT.KEY_VALUE, classification=Classification.RESTRICTED)

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
    categories = [v for k, v in attributes.get("categories", {}).items()]
    body_dict = {
        "Categories": ", ".join(categories),
        "Scan Date": format_time_from_epoch(attributes['last_analysis_date']),
        "First Seen": format_time_from_epoch(attributes['first_submission_date']),
        "Last Seen": format_time_from_epoch(attributes['last_submission_date']),
        "Permalink": f"https://www.virustotal.com/gui/url/{doc['id']}",
        "Reputation": attributes['reputation']
    }
    if hit_list:
        body_dict['Detected By'] = ", ".join(hit_list)
    elif und_list:
        body_dict['Undetected By'] = ", ".join(und_list)

    section_title = attributes['url']
    if attributes.get("title", None):
        section_title += f" ({attributes['title']})"

    main_section = ResultSection(section_title)

    # Submission meta
    ResultSection("VirusTotal Statistics", body=json.dumps(body_dict), body_format=BODY_FORMAT.KEY_VALUE,
                  parent=main_section, classification=Classification.UNRESTRICTED)

    submitter = context.get('submitter', None)
    if submitter:
        ResultSection("Submitter details", body=json.dumps(submitter), body_format=BODY_FORMAT.KEY_VALUE,
                      classification=Classification.RESTRICTED, parent=main_section)

    # TODO: Evaluate if URL is malicious before adding heuristic
    main_section.set_heuristic(2)
    [main_section.heuristic.add_signature_id(sig) for sig in sig_list]

    # Tags
    main_section.add_tag('network.static.uri', attributes['url'])
    return main_section


def attach_ontology(helper: OntologyHelper, doc: dict):
    return
