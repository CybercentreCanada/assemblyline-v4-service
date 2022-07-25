from assemblyline.odm.models.ontology.results import Sandbox, Process
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection, Heuristic
from collections import defaultdict

import json

SANDBOX_SIGNATURES = {
    'Adware': [],
    'Anti-analysis': [],
    'Anti-antivirus': [],
    'Anti-debug': [],
    'Anti-emulation': [],
    'Anti-sandbox': [],
    'Anti-vm': [],
    'AntiVirus Hit': [],
    'BOT': [],
    'Banker': [],
    'Bind': [],
    'Bypass': [],
    'C2': [],
    'Cloud': [],
    'Crash': [],
    'Cryptocurrency': [],
    'Downloader': [],
    'Dropper': [],
    'DynDNS': [],
    'Exploit': [],
    'Fraud': [],
    'Hacking tool': [],
    'IM': [],
    'Infostealer': [],
    'Injection': [],
    'Locker': [],
    'Packer': [],
    'Persistence': [],
    'Point-of-sale': [],
    'PowerShell': [],
    'RAT': [],
    'Ransomware': [],
    'Rootkit': [],
    'Rop': [],
    'Stealth': [],
    'Suspicious Android API': [],
    'Suspicious DLL': [],
    'Suspicious Execution Chain': [],
    'Suspicious Office': [],
    'Suspicious PDF API': [],
    'Tor': [],
    'Trojan': [],
    'URLshort': [],
    'Virus': [],
    'WMI': [],
    'Web Mail': [],
    'Worm': []
}

SANDBOX_SIGNATURES_REVERSE_LOOKUP = {sig_item: heuristic for heuristic,
                                     signatures in SANDBOX_SIGNATURES.items() for sig_item in signatures}


def get_events(so: SandboxOntology, process_tree=[], parent=None, execution_time=0):
    events = []
    for process in process_tree:
        ppid = parent.pid if parent else None
        pid = process['process_id']
        command_split = process['name'].split(" ")
        image = f'{command_split[0]} {command_split[1]}' if 'Program Files' in process['name'] else command_split[0]
        command = process['name']
        execution_time = execution_time+process.get('time_offset', 0)
        p = so.create_process(
            pobjectid=None,
            ppid=ppid,
            pid=pid,
            image=image,
            command_line=command,
            start_time=execution_time
        )
        so.add_process(p)
        get_events(so, process.get('children', []), parent=p, execution_time=execution_time)


# Modeling output after Cuckoo service
def v3(doc: dict):
    def get_process_tree(so: SandboxOntology, processes_tree=[], parent_section=None, execution_time=0):
        get_events(so, processes_tree, execution_time=execution_time)

        if not so.get_events():
            return

        process_tree_res_sec = so.get_process_tree_result_section()
        process_tree_res_sec.auto_collapse = True
        parent_section.add_subsection(process_tree_res_sec)

    def get_network_activity(dns_lookups=[], http_conv=[], ids_alerts=[], parent_section=None):
        network_section = ResultSection('Network Activity')
        if dns_lookups:
            lookup_table = []
            domains = []
            ips = []
            reverse_lookup_table = {}

            # DNS Lookup Table
            for record in dns_lookups:
                domain = record['hostname']
                resolved_ips = record.get('resolved_ips', [])
                lookup_table.append({
                    'domain': domain,
                    'addresses': resolved_ips
                })
                domains.append(record['hostname'])
                ips += resolved_ips
                [reverse_lookup_table.update({ip: domain}) for ip in resolved_ips]

            # Network Alerts Table
            id_map = defaultdict(lambda: {})
            [id_map[id['alert_severity']].update({id['alert_context'][ip_field]: id['rule_msg']})
             for id in ids_alerts if id.get('alert_context', False)
             for ip_field in id['alert_context'].keys() if '_ip' in ip_field]

            if id_map:
                alerts_section = ResultSection('Network Alerts', parent=network_section)
                for severity in ['high', 'medium', 'low']:
                    severity_table, severity_ip, severity_domain = [], [], []
                    for ip, msg in id_map[severity].items():
                        domain = reverse_lookup_table.get(ip, "Unknown Domain")
                        if domain != "Unknown Domain":
                            severity_domain.append(domain)
                        severity_ip.append(ip)
                        severity_table.append({
                            'IP': ip,
                            'rule_msg': msg
                        })
                    if severity_table:
                        ResultSection(
                            f'Severity: {severity}', body=json.dumps(severity_table),
                            body_format=BODY_FORMAT.TABLE, parent=alerts_section,
                            heuristic=Heuristic(2, signature=severity),
                            tags={'network.dynamic.domain': severity_domain, 'network.dynamic.ip': severity_ip})

            ResultSection('Protocol: DNS', body_format=BODY_FORMAT.TABLE, parent=network_section,
                          body=json.dumps(lookup_table), auto_collapse=True,
                          tags={'network.dynamic.domain': domains, 'network.dynamic.ip': ips})

        # HTTP Traffic Table
        if http_conv:
            http_conversations = []
            tags = []
            for http in http_conv:
                http_conversations.append({
                    'protocol':  http['url'].split('://')[0],
                    'request': f"{http['request_method']} {http['url']}"
                })
                tags.append(http['url'])

            ResultSection('Protocol: HTTP/HTTPS', body_format=BODY_FORMAT.TABLE, parent=network_section,
                          body=json.dumps(http_conversations), tags={'network.dynamic.uri': tags}, auto_collapse=True)

        if network_section.subsections:
            parent_section.add_subsection(network_section)

    def get_signatures(highlights=[], parent_section=None):
        signatures_map = defaultdict(lambda: [])
        [signatures_map[SANDBOX_SIGNATURES_REVERSE_LOOKUP.get(
            highlight, 'Unknown')].append(highlight) for highlight in highlights]
        if signatures_map:
            ResultSection('Signatures', body=json.dumps(signatures_map), body_format=BODY_FORMAT.KEY_VALUE,
                          parent=parent_section)

    attributes = doc['attributes']
    sandbox_section = ResultSection(f"Sandbox: {attributes['sandbox_name']}")
    # get_signatures(attributes.get('tags', []) + attributes.get('calls_highlighted', []),
    #             parent_section=sandbox_section)
    so = SandboxOntology()
    get_process_tree(so, attributes.get('processes_tree', []), parent_section=sandbox_section,
                     execution_time=attributes['analysis_date'])
    get_network_activity(attributes.get('dns_lookups', []), attributes.get('http_conversations', []),
                         attributes.get('ids_alerts', []), parent_section=sandbox_section)
    if sandbox_section.subsections:
        return sandbox_section


def attach_ontology(ontology_helper: OntologyHelper, doc: dict):
    attributes = doc["attributes"]
    so_ontology = {
        "sandbox_name": attributes['sandbox_name'],
        "analysis_metadata": {
            "start_time": attributes['analysis_date'],
        }
    }
    ontology_id = Sandbox.get_oid(so_ontology)
    so_ontology['objectid'] = {
        'ontology_id': ontology_id,
        'session': ontology_id
    }
    session_id = ontology_helper.add_result_part(Sandbox, so_ontology)
    so = SandboxOntology()
    get_events(so, attributes.get('processes_tree', []), execution_time=attributes['analysis_date'])
    for process_event in so.get_events():
        proc = process_event.as_primitives()
        proc['objectid']['session'] = session_id

        if proc['end_time'] == float('inf'):
            proc['end_time'] = None
        ontology_helper.add_result_part(Process, proc)

    return
