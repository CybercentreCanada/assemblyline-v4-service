import json
import os
import random
import tempfile

from assemblyline.common import forge
from assemblyline.common.attack_map import software_map, attack_map, group_map, revoke_map
from assemblyline.common.dict_utils import flatten
from assemblyline.common.hexdump import hexdump
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic

# DO NOT IMPORT IN YOUR SERVICE. These are just for creating randomized results.
from assemblyline.odm.randomizer import get_random_phrase, get_random_ip, get_random_host, get_random_tags
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
            text_section = ResultSection('Example of a default section')
            # You can add lines to your section one at a time
            #   Here we will generate a random line
            text_section.add_line(get_random_phrase())
            # Or your can add them from a list
            #   Here we will generate random amount of random lines
            text_section.add_lines([get_random_phrase() for _ in range(random.randint(1, 5))])
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
            color_map_data = {
                'type': 'colormap',
                'data': {
                    'domain': [cmap_min, cmap_max],
                    'values': [random.random() * cmap_max for _ in range(50)]
                }
            }
            # The classification of a section can be set to any valid classification for your system
            section_color_map = ResultSection("Example of colormap result section", body_format=BODY_FORMAT.GRAPH_DATA,
                                              body=json.dumps(color_map_data), classification=cl_engine.RESTRICTED)
            result.add_section(section_color_map)

            # ==================================================================
            # URL section: BODY_FORMAT.URL
            #   Generate a list of clickable urls using a json encoded format
            #     As you can see here, the body of the section can be set directly instead of line by line
            random_host = get_random_host()
            url_section = ResultSection('Example of a simple url section', body_format=BODY_FORMAT.URL,
                                        body=json.dumps({"name": "Random url!", "url": f"https://{random_host}/"}))

            # Since urls are very important features we can tag those features in the system so they are easy to find
            #   Tags are defined by a type and a value
            url_section.add_tag("network.static.domain", random_host)

            # You may also want to provide a list of url!
            #   Also, No need to provide a name, the url link will be displayed
            host1 = get_random_host()
            host2 = get_random_host()
            urls = [
                {"url": f"https://{host1}/"},
                {"url": f"https://{host2}/"}]

            # A heuristic can fire more then once without being associated to a signature
            url_heuristic = Heuristic(4, frequency=len(urls))

            url_sub_section = ResultSection('Example of a url sub-section with multiple links',
                                            body=json.dumps(urls), body_format=BODY_FORMAT.URL,
                                            heuristic=url_heuristic, classification=cl_engine.RESTRICTED)
            url_sub_section.add_tag("network.static.domain", host1)
            url_sub_section.add_tag("network.dynamic.domain", host2)

            # You can keep nesting sections if you really need to
            ip1 = get_random_ip()
            ip2 = get_random_ip()
            ip3 = get_random_ip()
            ips = [
                {"url": f"https://{ip1}/"},
                {"url": f"https://{ip2}/"},
                {"url": f"https://{ip3}/"}]
            url_sub_sub_section = ResultSection('Exemple of a two level deep sub-section',
                                                body=json.dumps(ips), body_format=BODY_FORMAT.URL)
            url_sub_sub_section.add_tag("network.static.ip", ip1)
            url_sub_sub_section.add_tag("network.static.ip", ip2)
            url_sub_sub_section.add_tag("network.static.ip", ip3)

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
            memdump_section = ResultSection('Example of a memory dump section', body_format=BODY_FORMAT.MEMORY_DUMP,
                                            body=data)
            memdump_section.set_heuristic(random.randint(1, 4))
            result.add_section(memdump_section)

            # ==================================================================
            # KEY_VALUE section:
            #     This section allows the service writer to list a bunch of key/value pairs to be displayed in the UI
            #     while also providing easy to parse data for auto mated tools.
            #     NB: You should definitely use this over a JSON body type since this one will be displayed correctly
            #         in the UI for the user
            #     The body argument must be a json dumps of a dictionary (only str, int, and booleans are allowed)
            kv_body = {
                "a_str": "Some string",
                "a_bool": False,
                "an_int": 102,
            }
            kv_section = ResultSection('Example of a KEY_VALUE section', body_format=BODY_FORMAT.KEY_VALUE,
                                       body=json.dumps(kv_body))
            result.add_section(kv_section)

            # ==================================================================
            # JSON section:
            #     Re-use the JSON editor we use for administration (https://github.com/josdejong/jsoneditor)
            #     to display a tree view of JSON results.
            #     NB: Use this sparingly! As a service developer you should do your best to include important
            #     results as their own result sections.
            #     The body argument must be a json dump of a python dictionary
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
            json_section = ResultSection('Example of a JSON section', body_format=BODY_FORMAT.JSON,
                                         body=json.dumps(json_body))
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
            #       "children": [] NB: This list either is empty or contains more dictionaries that have the same
            #                          structure
            #     }
            nc_body = [
                {
                    "process_pid": 123,
                    "process_name": "evil.exe",
                    "command_line": "C:\\evil.exe",
                    "signatures": {},
                    "children": [
                        {
                            "process_pid": 321,
                            "process_name": "takeovercomputer.exe",
                            "command_line": "C:\\Temp\\takeovercomputer.exe -f do_bad_stuff",
                            "signatures": {"one": 250},
                            "children": [
                                {
                                    "process_pid": 456,
                                    "process_name": "evenworsethanbefore.exe",
                                    "command_line": "C:\\Temp\\evenworsethanbefore.exe -f change_reg_key_cuz_im_bad",
                                    "signatures": {"one": 10, "two": 10, "three": 10},
                                    "children": []
                                },
                                {
                                    "process_pid": 234,
                                    "process_name": "badfile.exe",
                                    "command_line": "C:\\badfile.exe -k nothing_to_see_here",
                                    "signatures": {"one": 1000, "two": 10, "three": 10, "four": 10, "five": 10},
                                    "children": []
                                }
                            ]
                        },
                        {
                            "process_pid": 345,
                            "process_name": "benignexe.exe",
                            "command_line": "C:\\benignexe.exe -f \"just kidding, i'm evil\"",
                            "signatures": {"one": 2000},
                            "children": []
                        }
                    ]
                },
                {
                    "process_pid": 987,
                    "process_name": "runzeroday.exe",
                    "command_line": "C:\\runzeroday.exe -f insert_bad_spelling",
                    "signatures": {},
                    "children": []
                }
            ]
            nc_section = ResultSection('Example of a PROCESS_TREE section',
                                       body_format=BODY_FORMAT.PROCESS_TREE,
                                       body=json.dumps(nc_body))
            result.add_section(nc_section)

            # ==================================================================
            # TABLE section:
            #     This section allows the service writer to have their content displayed in a table format in the UI
            #     The body argument must be a list [] of dict {} objects. A dict object can have a key value pair
            #     where the value is a flat nested dictionary, and this nested dictionary will be displayed as a nested
            #     table within a cell.
            table_body = [
                {
                    "a_str": "Some string1",
                    "extra_column_here": "confirmed",
                    "a_bool": False,
                    "an_int": 101,
                },
                {
                    "a_str": "Some string2",
                    "a_bool": True,
                    "an_int": 102,
                },
                {
                    "a_str": "Some string3",
                    "a_bool": False,
                    "an_int": 103,
                },
                {
                    "a_str": "Some string4",
                    "a_bool": None,
                    "an_int": -1000000000000000000,
                    "extra_column_there": "confirmed",
                    "nested_table": {
                        "a_str": "Some string3",
                        "a_bool": False,
                        "nested_table_thats_too_deep": {
                            "a_str": "Some string3",
                            "a_bool": False,
                            "an_int": 103,
                        },
                    },
                },
            ]
            table_section = ResultSection('Example of a TABLE section',
                                          body_format=BODY_FORMAT.TABLE,
                                          body=json.dumps(table_body))
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
                myfile.write(json.dumps(urls))
            request.add_supplementary(temp_path, "urls.json", "These are urls as a JSON file")
            # like embedded files, you can add more then one supplementary files
            fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
            with os.fdopen(fd, "w") as myfile:
                myfile.write(json.dumps(json_body))
            request.add_supplementary(temp_path, "json_body.json", "This is the json_body as a JSON file")

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
