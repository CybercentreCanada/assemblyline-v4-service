import json
import os
import random
import tempfile

from assemblyline.common import forge
from assemblyline.common.attack_map import attack_map, group_map, revoke_map, software_map
from assemblyline.common.dict_utils import flatten
from assemblyline.common.hexdump import hexdump

# DO NOT IMPORT IN YOUR SERVICE. These are just for creating randomized results.
from assemblyline.odm.randomizer import get_random_host, get_random_ip, get_random_phrase, get_random_tags
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    DividerSectionBody,
    GraphSectionBody,
    Heuristic,
    KVSectionBody,
    ProcessItem,
    Result,
    ResultGraphSection,
    ResultImageSection,
    ResultJSONSection,
    ResultKeyValueSection,
    ResultMemoryDumpSection,
    ResultMultiSection,
    ResultOrderedKeyValueSection,
    ResultProcessTreeSection,
    ResultSandboxSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    ResultTimelineSection,
    ResultURLSection,
    SandboxAnalysisMetadata,
    SandboxAttackItem,
    SandboxMachineMetadata,
    SandboxNetflowItem,
    SandboxNetworkDNS,
    SandboxNetworkHTTP,
    SandboxNetworkSMTP,
    SandboxProcessItem,
    SandboxSignatureItem,
    TableRow,
    TextSectionBody,
)

# DO NOT LIST BODY FORMATS LIKE THIS. This is again for the data randomizer.
FORMAT_LIST = [BODY_FORMAT.TEXT, BODY_FORMAT.MEMORY_DUMP]

cl_engine = forge.get_classification()


class ResultSample(ServiceBase):
    def __init__(self, config=None):
        super(ResultSample, self).__init__(config)

    def start(self):
        # ==================================================================
        # On Startup actions:
        #   Your service might have to do some warming up on startup to make things faster

        self.log.info(f"start() from {self.service_attributes.name} service called")

    def execute(self, request):
        # ==================================================================
        # Execute a request:
        #   Every time your service receives a new file to scan, the execute function is called
        #   This is where you should execute your processing code.
        #   For the purpose of this example, we will only generate results ...

        # You should run your code here...

        # ==================================================================
        # Check if we're scanning an embedded file
        #   This service always drop 3 embedded file which two generates random results and the other empty results
        #   We're making a check to see if we're scanning the embedded file.
        #   In a normal service this is not something you would do at all but since we are using this
        #   service in our unit test to test all features of our report generator, we have to do this
        if request.sha256 not in ['d729ecfb2cf40bc4af8038dac609a57f57dbe6515d35357af973677d5e66417a',
                                  '5ce5ae8ef56a54af2c44415800a81ecffd49a33ae8895dfe38fc1075d3f619ec',
                                  'cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06']:
            # Main file results...

            # ==================================================================
            # Write the results:
            #   First, create a result object where all the result sections will be saved to
            result = Result()

            # ==================================================================
            # Standard text section: BODY_FORMAT.TEXT - DEFAULT
            #   Text sections basically just dumps the text to the screen...
            #     All sections scores will be SUMed in the service result
            #     The Result classification will be the highest classification found in the sections
            text_section = ResultTextSection('Example of a default section')
            # You can add lines to your section one at a time
            #   Here we will generate a random line
            text_section.add_line(get_random_phrase())
            # Or your can add them from a list
            #   Here we will generate random amount of random lines
            text_section.add_lines([get_random_phrase() for _ in range(random.randint(1, 5))])
            # You can tag data to a section, tagging is used to to quickly find defining information about a file
            text_section.add_tag("attribution.implant", "ResultSample")
            # If the section needs to affect the score of the file you need to set a heuristics
            #   Here we will pick one at random
            #     In addition to add a heuristic, we will associated a signature with the heuristic,
            #     we're doing this by adding the signature name to the heuristic. (Here we generating a random name)
            text_section.set_heuristic(3, signature="sig_one")
            # You can attach attack ids to heuristics after they where defined
            text_section.heuristic.add_attack_id(random.choice(list(software_map.keys())))
            text_section.heuristic.add_attack_id(random.choice(list(attack_map.keys())))
            text_section.heuristic.add_attack_id(random.choice(list(group_map.keys())))
            text_section.heuristic.add_attack_id(random.choice(list(revoke_map.keys())))
            # Same thing for the signatures, they can be added to heuristic after the fact and you can even say how
            #   many time the signature fired by setting its frequency. If you call add_signature_id twice with the
            #   same signature, this will effectively increase the frequency of the signature.
            text_section.heuristic.add_signature_id("sig_two", score=20, frequency=2)
            text_section.heuristic.add_signature_id("sig_two", score=20, frequency=3)
            text_section.heuristic.add_signature_id("sig_three")
            text_section.heuristic.add_signature_id("sig_three")
            text_section.heuristic.add_signature_id("sig_four", score=0)
            # The heuristic for text_section should have the following properties
            #   1. 1 attack ID: T1066
            #   2. 4 signatures: sig_one, sig_two, sig_three and sig_four
            #   3. Signature frequencies are cumulative therefor they will be as follow:
            #      - sig_one = 1
            #      - sig_two = 5
            #      - sig_three = 2
            #      - sig_four = 1
            #   4. The score used by each heuristic is driven by the following rules: signature_score_map is higher
            #      priority, then score value for the add_signature_id is in second place and finally the default
            #      heuristic score is use. Therefor the score used to calculate the total score for the text_section is
            #      as follow:
            #      - sig_one: 10    -> heuristic default score
            #      - sig_two: 20    -> score provided by the function add_signature_id
            #      - sig_three: 30  -> score provided by the heuristic map
            #      - sig_four: 40   -> score provided by the heuristic map because it's higher priority than the
            #                          function score
            #    5. Total section score is then: 1x10 + 5x20 + 2x30 + 1x40 = 210
            # Make sure you add your section to the result
            result.add_section(text_section)

            # Even if the section was added to the results you can still modify it by adding a subsection for example
            ResultSection("Example of sub-section without a body added later in processing", parent=text_section)

            # ==================================================================
            # Color map Section: BODY_FORMAT.GRAPH_DATA
            #     Creates a color map bar using a minimum and maximum domain
            #     e.g. We are using this section to display the entropy distribution in some services
            cmap_min = 0
            cmap_max = 20
            cmap_values = [random.random() * cmap_max for _ in range(50)]
            # The classification of a section can be set to any valid classification for your system
            section_color_map = ResultGraphSection(
                "Example of colormap result section", classification=cl_engine.RESTRICTED)
            section_color_map.set_colormap(cmap_min, cmap_max, cmap_values)
            section_color_map.promote_as_entropy()
            result.add_section(section_color_map)

            # ==================================================================
            # URL section: BODY_FORMAT.URL
            #   Generate a list of clickable urls using a json encoded format
            #     As you can see here, the body of the section can be set directly instead of line by line
            random_host = get_random_host()
            url_section = ResultURLSection('Example of a simple url section')
            url_section.add_url(f"https://{random_host}/", name="Random url!")

            # Since urls are very important features we can tag those features in the system so they are easy to find
            #   Tags are defined by a type and a value
            url_section.add_tag("network.static.domain", random_host)
            url_section.add_tag("network.static.uri", f"https://{random_host}/")

            # You may also want to provide a list of url!
            #   Also, No need to provide a name, the url link will be displayed
            hosts = [get_random_host() for _ in range(2)]

            # A heuristic can fire more then once without being associated to a signature
            url_heuristic = Heuristic(4, frequency=len(hosts))

            url_sub_section = ResultURLSection('Example of a url sub-section with multiple links',
                                               heuristic=url_heuristic, classification=cl_engine.RESTRICTED)
            for host in hosts:
                url_sub_section.add_url(f"https://{host}/")
                url_sub_section.add_tag("network.static.domain", host)
                url_sub_section.add_tag("network.static.uri", f"https://{host}/")

            # You can keep nesting sections if you really need to
            ips = [get_random_ip() for _ in range(3)]
            url_sub_sub_section = ResultURLSection('Exemple of a two level deep sub-section')
            for ip in ips:
                url_sub_sub_section.add_url(f"https://{ip}/")
                url_sub_sub_section.add_tag("network.static.ip", ip)
                url_sub_sub_section.add_tag("network.static.uri", f"https://{ip}/")

            # Since url_sub_sub_section is a sub-section of url_sub_section
            # we will add it as a sub-section of url_sub_section not to the main result itself
            url_sub_section.add_subsection(url_sub_sub_section)

            # Invalid sections will be ignored, and an error will apear in the logs
            # Sub-sections of invalid sections will be ignored too
            invalid_section = ResultSection("")
            ResultSection("I won't make it to the report because my parent is invalid :(", parent=invalid_section)
            url_sub_section.add_subsection(invalid_section)

            # Since url_sub_section is a sub-section of url_section
            # we will add it as a sub-section of url_section not to the main result itself
            url_section.add_subsection(url_sub_section)

            result.add_section(url_section)

            # ==================================================================
            # Memory dump section: BODY_FORMAT.MEMORY_DUMP
            #     Dump whatever string content you have into a <pre/> html tag so you can do your own formatting
            data = hexdump(b"This is some random text that we will format as an hexdump and you'll see "
                           b"that the hexdump formatting will be preserved by the memory dump section!")
            memdump_section = ResultMemoryDumpSection('Example of a memory dump section', body=data)
            memdump_section.set_heuristic(random.randint(1, 4))
            result.add_section(memdump_section)

            # ==================================================================
            # KEY_VALUE section:
            #     This section allows the service writer to list a bunch of key/value pairs to be displayed in the UI
            #     while also providing easy to parse data for auto mated tools.
            #     NB: You should definitely use this over a JSON body type since this one will be displayed correctly
            #         in the UI for the user
            #     The body argument must be a dictionary (only str, int, and booleans are allowed)
            kv_section = ResultKeyValueSection('Example of a KEY_VALUE section')
            # You can add items individually
            kv_section.set_item('key', "value")
            # Or simply add them in bulk
            kv_section.update_items({
                "a_str": "Some string",
                "a_bool": False,
                "an_int": 102,
            })
            result.add_section(kv_section)

            # ==================================================================
            # ORDERED_KEY_VALUE section:
            #     This section provides the same functionality as the KEY_VALUE section except the order of the fields
            #     are garanteed to be preserved in the order in which the fields are added to the section. Also with
            #     this section, you can repeat the same key name multiple times
            oredered_kv_section = ResultOrderedKeyValueSection('Example of an ORDERED_KEY_VALUE section')
            # You can add items individually
            for x in range(random.randint(3, 6)):
                oredered_kv_section.add_item(f'key{x}', f"value{x}")

            result.add_section(oredered_kv_section)

            # ==================================================================
            # JSON section:
            #     Re-use the JSON editor we use for administration (https://github.com/josdejong/jsoneditor)
            #     to display a tree view of JSON results.
            #     NB: Use this sparingly! As a service developer you should do your best to include important
            #     results as their own result sections.
            #     The body argument must be a python dictionary
            json_body = {
                "a_str": "Some string",
                "a_list": ["a", "b", "c"],
                "a_bool": False,
                "an_int": 102,
                "a_dict": {
                    "list_of_dict": [
                        {"d1_key": "val", "d1_key2": "val2"},
                        {"d2_key": "val", "d2_key2": "val2"}
                    ],
                    "bool": True
                }
            }
            json_section = ResultJSONSection('Example of a JSON section')
            # You can set the json result to a specific value
            json_section.set_json(json_body)
            # You can also update specific parts after the fact
            json_section.update_json({'an_int': 1000, 'updated_key': 'updated_value'})

            result.add_section(json_section)

            # ==================================================================
            # PROCESS_TREE section:
            #     This section allows the service writer to list a bunch of dictionary objects that have nested lists
            #     of dictionaries to be displayed in the UI. Each dictionary object represents a process, and therefore
            #     each dictionary must have be of the following format:
            #     {
            #       "process_pid": int,
            #       "process_name": str,
            #       "command_line": str,
            #       "signatures": {}  This dict has the signature name as a key and the score as it's value
            #       "children": []    NB: This list either is empty or contains more dictionaries that have the same
            #                             structure
            #     }
            process_tree_section = ResultProcessTreeSection('Example of a PROCESS_TREE section')
            # You can use the ProcessItem class to create the processes to add to the result section
            evil_process = ProcessItem(123, "evil.exe", "c:\\evil.exe")
            evil_process_child_1 = ProcessItem(321, "takeovercomputer.exe",
                                               "C:\\Temp\\takeovercomputer.exe -f do_bad_stuff")
            # You can add child processes to the ProcessItem objects
            evil_process_child_1.add_child_process(
                ProcessItem(
                    456, "evenworsethanbefore.exe",
                    "C:\\Temp\\evenworsethanbefore.exe -f change_reg_key_cuz_im_bad",
                    signatures={"one": 10, "two": 10, "three": 10}))
            evil_process_child_1.add_child_process(
                ProcessItem(
                    234, "badfile.exe", "C:\\badfile.exe -k nothing_to_see_here",
                    signatures={"one": 1000, "two": 10, "three": 10, "four": 10, "five": 10}))

            # You can add signatures that hit on a ProcessItem Object
            evil_process_child_1.add_signature('one', 250)

            # Or even directly create the ProcessItem object with the signature in it
            evil_process_child_2 = ProcessItem(
                345, "benignexe.exe", "C:\\benignexe.exe -f \"just kidding, i'm evil\"", signatures={"one": 2000})

            # You can also add counts for network, file and registry events to a ProcessItem object
            evil_process_child_2.add_network_events(4)
            evil_process_child_2.add_file_events(7000)
            evil_process_child_2.add_registry_events(10)

            # You can also indicate if the process tree item has been safelisted
            benign_process = ProcessItem(678, "trustme.exe", "C:\\trustme.exe")
            benign_process.safelist()

            evil_process.add_child_process(evil_process_child_1)
            evil_process.add_child_process(evil_process_child_2)

            # Add your processes to the result section via the add_process function
            process_tree_section.add_process(evil_process)
            process_tree_section.add_process(ProcessItem(
                987, "runzeroday.exe", "C:\\runzeroday.exe -f insert_bad_spelling"))
            process_tree_section.add_process(benign_process)

            result.add_section(process_tree_section)

            # ==================================================================
            # SANDBOX section:
            #     This section allows a service writer to structure and enrich sandbox analysis
            #     results with key metadata, processes, network connections, and detection signatures.
            #     Each element is represented by its own item class (SandboxProcessItem, SandboxNetflowItem, etc.).
            # ==================================================================
            sandbox_section = ResultSandboxSection("Example of a SANDBOX section")

            # Sandbox information
            sandbox_section.set_sandbox(
                name="Cuckoo Sandbox",
                version="2.0.7",
                machine_metadata=SandboxMachineMetadata(
                    ip="192.168.0.15",
                    hypervisor="KVM",
                    hostname="analysis-vm-01",
                    platform="Windows",
                    version="10.0.19045",
                    architecture="x64"
                ),
                analysis_metadata=SandboxAnalysisMetadata(
                    task_id="task_001",
                    start_time="2025-10-14T12:00:00Z",
                    end_time="2025-10-14T12:10:30Z",
                    routing="Internet",
                    window_size="1024x768",
                )
            )

            # Processes
            sandbox_section.add_process(SandboxProcessItem(
                image="C:\\Windows\\System32\\svchost.exe",
                start_time="2025-10-14T12:00:02Z",
                end_time="2025-10-14T12:01:00Z",
                pid=50,
                ppid=4,
                command_line="svchost.exe -k netsvcs",
                integrity_level="system",
                image_hash="svchosthash001",
                original_file_name="svchost.exe",
                safelisted=True,
            ))

            sandbox_section.add_process(SandboxProcessItem(
                image="cmd.exe",
                start_time="2025-10-14T12:00:05Z",
                end_time="2025-10-14T12:00:40Z",
                pid=100,
                ppid=50,
                command_line="C:\\Windows\\System32\\cmd.exe /c badscript.bat",
                integrity_level="medium",
                image_hash="badhash123",
                original_file_name="CMD.EXE",
                safelisted=False,
                file_count=5,
                registry_count=1,
            ))

            sandbox_section.add_process(SandboxProcessItem(
                image="powershell.exe",
                start_time="2025-10-14T12:00:10Z",
                end_time="2025-10-14T12:00:45Z",
                pid=120,
                ppid=100,
                command_line="powershell.exe -enc aQBmACgA",
                integrity_level="high",
                image_hash="evilhash789",
                safelisted=False,
            ))

            sandbox_section.add_process(SandboxProcessItem(
                image="C:\\Windows\\System32\\explorer.exe",
                start_time="2025-10-14T12:00:03Z",
                end_time="2025-10-14T12:01:10Z",
                pid=200,
                ppid=50,
                command_line="explorer.exe",
                integrity_level="medium",
                image_hash="explorerhash002",
                original_file_name="EXPLORER.EXE",
                safelisted=True,
            ))

            sandbox_section.add_process(SandboxProcessItem(
                image="notepad.exe",
                start_time="2025-10-14T12:00:25Z",
                end_time="2025-10-14T12:00:55Z",
                pid=140,
                ppid=120,
                command_line="notepad.exe suspicious.txt",
                integrity_level="medium",
                image_hash="notehash333",
                safelisted=False,
            ))

            sandbox_section.add_process(SandboxProcessItem(
                image="C:\\Windows\\System32\\wscript.exe",
                start_time="2025-10-14T12:00:30Z",
                end_time="2025-10-14T12:00:50Z",
                pid=160,
                ppid=100,
                command_line="wscript.exe //B //E:js badscript.js",
                integrity_level="medium",
                image_hash="wskripthash444",
                safelisted=False,
            ))

            sandbox_section.add_process(SandboxProcessItem(
                image="C:\\ProgramData\\malware\\injector.exe",
                start_time="2025-10-14T12:00:35Z",
                end_time="2025-10-14T12:00:55Z",
                pid=180,
                ppid=160,
                command_line="injector.exe -target svchost.exe",
                integrity_level="high",
                image_hash="injectorhash555",
                safelisted=False,
            ))

            sandbox_section.add_process(SandboxProcessItem(
                image="C:\\Temp\\dropper.exe",
                start_time="2025-10-14T12:00:40Z",
                end_time="2025-10-14T12:00:58Z",
                pid=220,
                ppid=120,
                command_line="dropper.exe --silent",
                integrity_level="medium",
                image_hash="drophere666",
                safelisted=False,
            ))

            sandbox_section.add_process(SandboxProcessItem(
                image="chrome.exe",
                start_time="2025-10-14T12:00:45Z",
                end_time="2025-10-14T12:01:15Z",
                pid=240,
                ppid=200,
                command_line="chrome.exe --remote-debugging",
                integrity_level="medium",
                image_hash="chromehash777",
                safelisted=True,
            ))

            sandbox_section.add_process(SandboxProcessItem(
                image="C:\\Users\\Public\\payload.exe",
                start_time="2025-10-14T12:00:50Z",
                end_time="2025-10-14T12:01:05Z",
                pid=260,
                ppid=220,
                command_line="payload.exe --stealth",
                integrity_level="high",
                image_hash="payloadhash888",
                safelisted=False,
            ))

            # Network flows (HTTP example)
            sandbox_section.add_netflow(SandboxNetflowItem(
                destination_ip="45.83.23.19",
                destination_port=80,
                source_ip="192.168.0.15",
                source_port=54321,
                time_observed="2025-10-14T12:00:10Z",
                pid=120,
                direction="outbound",
                transport_layer_protocol="tcp",
                http_details=SandboxNetworkHTTP(
                    request_uri="http://malicious.example.com/payload.exe",
                    request_method="GET",
                    response_status_code=200,
                    response_content_mimetype="application/octet-stream",
                    request_headers={"User-Agent": "PowerShell"},
                ),
                connection_type="http"
            ))

            # Network flows (DNS example, minimal)
            sandbox_section.add_netflow(SandboxNetflowItem(
                pid=120,
                direction="outbound",
                time_observed="2025-10-14T12:00:10Z",
                dns_details=SandboxNetworkDNS(
                    domain="malicious.example.com",
                    lookup_type="A",
                    resolved_ips=["45.83.23.19"]
                ),
                connection_type="dns"
            ))

            # Network flows (SMTP example)
            sandbox_section.add_netflow(SandboxNetflowItem(
                destination_ip="203.0.113.55",
                destination_port=25,
                source_ip="192.168.0.15",
                source_port=60000,
                time_observed="2025-10-14T12:00:10Z",
                pid=100,
                direction="outbound",
                transport_layer_protocol="tcp",
                smtp_details=SandboxNetworkSMTP(
                    mail_from="attacker@example.com",
                    mail_to=["victim@example.com"],
                    attachments=[{"filename": "payload.docm", "size": 20480}]
                ),
                connection_type="smtp"
            ))

            sandbox_section.add_netflow(SandboxNetflowItem(
                destination_ip="8.8.8.8",
                destination_port=53,
                source_ip="192.168.0.15",
                source_port=50505,
                time_observed="2025-10-14T12:01:00Z",
                pid=140,
                direction="outbound",
                dns_details=SandboxNetworkDNS(domain="example.org", lookup_type="A", resolved_ips=["93.184.216.34"]),
                connection_type="dns"
            ))

            sandbox_section.add_netflow(SandboxNetflowItem(
                destination_ip="203.0.113.100",
                destination_port=8080,
                source_ip="192.168.0.15",
                source_port=50506,
                time_observed="2025-10-14T12:01:10Z",
                pid=160,
                direction="outbound",
                transport_layer_protocol="tcp",
                http_details=SandboxNetworkHTTP(
                    request_uri="http://203.0.113.100/c2",
                    request_method="POST",
                    response_status_code=404,
                    response_content_mimetype="text/plain",
                    request_headers={"User-Agent": "Mozilla/5.0"},
                ),
                connection_type="http"
            ))

            sandbox_section.add_netflow(SandboxNetflowItem(
                destination_ip="198.51.100.44",
                destination_port=443,
                source_ip="192.168.0.15",
                source_port=50507,
                time_observed="2025-10-14T12:01:12Z",
                pid=180,
                direction="outbound",
                transport_layer_protocol="tcp",
                connection_type="https"
            ))

            sandbox_section.add_netflow(SandboxNetflowItem(
                destination_ip="10.0.0.5",
                destination_port=21,
                source_ip="192.168.0.15",
                source_port=50508,
                time_observed="2025-10-14T12:01:15Z",
                pid=200,
                direction="outbound",
                transport_layer_protocol="tcp",
                connection_type="ftp"
            ))

            sandbox_section.add_netflow(SandboxNetflowItem(
                destination_ip="172.16.5.7",
                destination_port=8081,
                source_ip="192.168.0.15",
                source_port=50509,
                time_observed="2025-10-14T12:01:20Z",
                pid=220,
                direction="outbound",
                transport_layer_protocol="tcp",
                connection_type="tcp"
            ))

            # Signatures
            sandbox_section.add_signature(SandboxSignatureItem(
                name="Suspicious PowerShell Execution",
                type="CUCKOO",
                classification=cl_engine.RESTRICTED,
                signature_id="sig_1234",
                message="PowerShell launched with encoded commands",
                pids=[120],
                score=1000,
                attacks=[
                    SandboxAttackItem("T1059.001", "PowerShell execution", ["defense-evasion", "discovery"]),
                    SandboxAttackItem("T1055", "Injecting code into other processes", ["discovery"]),
                ],
                actors=["APT29"],
                malware_families=["Empire"],
            ))

            sandbox_section.add_signature(SandboxSignatureItem(
                name="Encoded Command Execution Detected",
                type="CUCKOO",
                classification=cl_engine.RESTRICTED,
                signature_id="sig_5678",
                message="Base64 encoded command usage identified",
                pids=[120],
                score=1000,
            ))

            sandbox_section.add_signature(SandboxSignatureItem(
                name="Suspicious DLL Loading",
                type="YARA",
                classification=cl_engine.RESTRICTED,
                signature_id="sig_2001",
                message="Process injected and loaded unexpected DLLs",
                pids=[180],
                score=800,
                attacks=[
                    SandboxAttackItem("T1055", "Process Injection", ["privilege-escalation"]),
                ],
                actors=["Unknown"],
                malware_families=["UnknownFamilyA"],
            ))

            sandbox_section.add_signature(SandboxSignatureItem(
                name="HTTP Beaconing Pattern",
                type="SIGMA",
                classification=cl_engine.RESTRICTED,
                signature_id="sig_2002",
                message="Periodic small HTTP posts consistent with beaconing",
                pids=[220],
                score=600,
                attacks=[
                    SandboxAttackItem("T1071.001", "Application layer protocol: Web protocols", ["command-and-control"]),
                ],
            ))

            sandbox_section.add_signature(SandboxSignatureItem(
                name="Domain Generation Algorithm (DGA) Traffic",
                type="SURICATA",
                classification=cl_engine.RESTRICTED,
                signature_id="sig_2003",
                message="High-entropy domain pattern observed",
                pids=[240],
                score=900,
                attacks=[
                    SandboxAttackItem("T1483", "Domain Generation Algorithms", ["command-and-control"]),
                ],
            ))

            sandbox_section.add_signature(SandboxSignatureItem(
                name="Email Attachment with Macro",
                type="CUCKOO",
                classification=cl_engine.RESTRICTED,
                signature_id="sig_2004",
                message="Attachment with embedded macros opened",
                pids=[100],
                score=700,
                attacks=[
                    SandboxAttackItem("T1204.002", "User Execution: Malicious File", ["initial-access"]),
                ],
                actors=["PhishGroupX"],
                malware_families=["MacroDropper"],
            ))

            sandbox_section.add_signature(SandboxSignatureItem(
                name="Autostart Persistence Created",
                type="YARA",
                classification=cl_engine.RESTRICTED,
                signature_id="sig_2005",
                message="New autorun registry key created",
                pids=[160],
                score=800,
                attacks=[
                    SandboxAttackItem("T1547.001", "Registry Run Keys / Startup Folder", ["persistence"]),
                ],
            ))

            sandbox_section.add_signature(SandboxSignatureItem(
                name="Credential Dumping Activity",
                type="CUCKOO",
                classification=cl_engine.RESTRICTED,
                signature_id="sig_2006",
                message="Call sequence consistent with credential dumping",
                pids=[180],
                score=950,
                attacks=[
                    SandboxAttackItem("T1003", "OS Credential Dumping", ["credential-access"]),
                ],
            ))

            sandbox_section.add_signature(SandboxSignatureItem(
                name="File Write to System Dir",
                type="SIGMA",
                classification=cl_engine.RESTRICTED,
                signature_id="sig_2007",
                message="Executable written to system directory",
                pids=[260],
                score=750,
                attacks=[
                    SandboxAttackItem("T1547", "Boot or Logon Autostart Execution", ["persistence"]),
                ],
            ))

            sandbox_section.add_signature(SandboxSignatureItem(
                name="PowerShell Suspicious Module Load",
                type="YARA",
                classification=cl_engine.RESTRICTED,
                signature_id="sig_2008",
                message="PowerShell loaded a module from temp path",
                pids=[120],
                score=1000,
                attacks=[
                    SandboxAttackItem("T1059.001", "PowerShell execution", ["execution"]),
                ],
            ))


            # Add the section to the result
            result.add_section(sandbox_section)

            # ==================================================================
            # TABLE section:
            #     This section allows the service writer to have their content displayed in a table format in the UI
            #     The body argument must be a list [] of dict {} objects. A dict object can have a key value pair
            #     where the value is a flat nested dictionary, and this nested dictionary will be displayed as a nested
            #     table within a cell.
            table_section = ResultTableSection('Example of a TABLE section')
            # Use the TableRow class to help adding row to the Table section
            table_section.add_row(TableRow(a_str="Some string1",
                                  extra_column_here="confirmed", a_bool=False, an_int=101))
            table_section.add_row(TableRow({"a_str": "Some string2",
                                            "a_bool": True, "an_int": "to_be_overriden_by_kwargs"}, an_int=102))
            table_section.add_row(TableRow(a_str="Some string3", a_bool=False, an_int=103))
            # Valid values for the items in the TableRow are: str, int, bool, None, or dict of those values
            table_section.add_row(TableRow(
                {"a_str": "Some string4", "a_bool": None, "an_int": -1000000000000000000},
                {"extra_column_there": "confirmed", "nested_key_value_pair": {
                    "a_str": "Some string3",
                    "a_bool": False,
                    "nested_kv_thats_too_deep": {
                        "a_str": "Some string3",
                        "a_bool": False,
                        "an_int": 103,
                    },
                }}))
            # Optional: Set custom column ordering for table.
            # Column order is automatically inferred/updated on `ResultTableSection.add_row()`.
            # Passing an empty list ([]) to `ResultTableSection.set_column_order()`
            # will display the columns in alphabetical order
            table_section.set_column_order(['a_str', 'a_bool', 'an_int', 'extra_column_there', 'nested_key_value_pair'])
            result.add_section(table_section)

            # ==================================================================
            # Re-Submitting files to the system
            #     Adding extracted files will have them resubmitted to the system for analysis

            # This file will generate random results on the next run
            fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
            with os.fdopen(fd, "wb") as myfile:
                myfile.write(data.encode())
            request.add_extracted(temp_path, "file.txt", "Extracted by some magic!")

            # Embedded files can also have their own classification!
            fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
            with os.fdopen(fd, "wb") as myfile:
                myfile.write(b"CLASSIFIED!!!__"+data.encode())
            request.add_extracted(temp_path, "classified.doc", "Classified file ... don't look",
                                  classification=cl_engine.RESTRICTED)

            # This file will generate empty results on the next run
            fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
            with os.fdopen(fd, "wb") as myfile:
                myfile.write(b"EMPTY")
            request.add_extracted(temp_path, "empty.txt", "Extracted empty resulting file")

            # ==================================================================
            # Supplementary files
            #     Adding supplementary files will save them on the datastore for future
            #      reference but wont reprocess those files.
            fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
            with os.fdopen(fd, "w") as myfile:
                myfile.write(url_sub_section.body)
            request.add_supplementary(temp_path, "urls.json", "These are urls as a JSON file")
            # like embedded files, you can add more then one supplementary files
            fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
            with os.fdopen(fd, "w") as myfile:
                myfile.write(json.dumps(json_body))
            request.add_supplementary(temp_path, "json_body.json", "This is the json_body as a JSON file")

            # ==================================================================
            # Zeroize on safe tags
            #     When this feature is turned on, the section will get its score set to zero if all its tags
            #     were safelisted by the safelisting engine
            zero_section = ResultSection('Example of zeroize-able section', zeroize_on_tag_safe=True)
            zero_section.set_heuristic(2)
            zero_section.add_line("This section will have a zero score if all tags are safelisted.")
            zero_section.add_tag('network.static.ip', '127.0.0.1')
            result.add_section(zero_section)

            # ==================================================================
            # Auto-collapse
            #     When this feature is turned on, the section will be collapsed when first displayed
            collapse_section = ResultSection('Example of auto-collapse section', auto_collapse=True)
            collapse_section.set_heuristic(2)
            collapse_section.add_line("This section was collapsed when first loaded in the UI")
            result.add_section(collapse_section)

            # ==================================================================
            # Image Section
            #     This type of section allows the service writer to display images to the user
            image_section = ResultImageSection(request, 'Example of Image section')
            img_dir = os.path.join(os.path.dirname(__file__), 'data')
            for fname in sorted(os.listdir(img_dir)):
                image_section.add_image(os.path.join(img_dir, fname), fname,
                                        f'ResultSample screenshot {fname.split(".")[0]}', ocr_heuristic_id=6)
            image_section.promote_as_screenshot()
            result.add_section(image_section)

            # ==================================================================
            # Timeline Section
            #     This type of section allows the service writer to create a visual timeline
            timeline_section = ResultTimelineSection("Timeline")
            for x in range(4):
                timeline_section.add_node(title=f"Node {x}", content=f"Description: {x}",
                                          opposite_content=f"Value: {x}")
            result.add_section(timeline_section)

            # ==================================================================
            # Multi Section
            #     This type of section allows the service writer to display multiple section types
            #     in the same result section. Here's a concrete exemple of this:
            multi_section = ResultMultiSection('Example of Multi-typed section')
            multi_section.add_section_part(TextSectionBody(body="We have detected very high entropy multiple sections "
                                                                "of your file, this section is most-likely packed or "
                                                                "encrypted.\n\nHere are affected sections:"))
            section_count = random.randint(1, 4)
            for x in range(section_count):
                multi_section.add_section_part(
                    KVSectionBody(section_name=f".UPX{x}", offset=f'0x00{8+x}000', size='4196 bytes'))
                graph_part = GraphSectionBody()
                graph_part.set_colormap(0, 8, [7 + random.random() for _ in range(20)])
                multi_section.add_section_part(graph_part)
                if x != section_count - 1:
                    multi_section.add_section_part(DividerSectionBody())
                multi_section.add_tag("file.pe.sections.name", f".UPX{x}")

            multi_section.set_heuristic(5)
            result.add_section(multi_section)

            # ==================================================================
            # Propagate temporary submission data to other services
            #   Sometimes two service can work in tandem were one extra some piece of information the other
            #   one uses to do it's work. This is how a service can set temporary data that other
            #   services that subscribe to can use.
            request.temp_submission_data['kv_section'] = kv_section.body
            request.temp_submission_data['process_tree_section'] = process_tree_section.body
            request.temp_submission_data['url_section'] = url_sub_section.body

            # ==================================================================
            # Wrap-up:
            #     Save your result object back into the request
            request.result = result

        # ==================================================================
        # Empty results file
        elif request.sha256 == 'cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06':
            # Creating and empty result object
            request.result = Result()

        # ==================================================================
        # Empty results file
        elif request.sha256 == '5ce5ae8ef56a54af2c44415800a81ecffd49a33ae8895dfe38fc1075d3f619ec':
            # Creating safe results
            result = Result()
            safe_section = ResultTextSection('This file is definitely safe', heuristic=Heuristic(7))
            result.add_section(safe_section)
            request.result = result

        # ==================================================================
        # Randomized results file
        else:
            # For the randomized  results file, we will completely randomize the results
            #   The content of those results do not matter since we've already showed you
            #   all the different result sections, tagging, heuristics and file upload functions
            embedded_result = Result()

            # random number of sections
            for _ in range(1, 3):
                embedded_result.add_section(self._create_random_section())

            request.result = embedded_result

    def _create_random_section(self):
        # choose a random body format
        body_format = random.choice(FORMAT_LIST)

        # create a section with a random title
        section = ResultSection(get_random_phrase(3, 7), body_format=body_format)

        # choose random amount of lines in the body
        for _ in range(1, 5):
            # generate random line
            section.add_line(get_random_phrase(5, 10))

        # choose random amount of tags
        tags = flatten(get_random_tags())
        for key, val in tags.items():
            for v in val:
                section.add_tag(key, v)

        # set a heuristic a third of the time
        if random.choice([False, False, True]):
            section.set_heuristic(random.randint(1, 4))

        # Create random sub-sections
        if random.choice([False, False, True]):
            section.add_subsection(self._create_random_section())

        return section
