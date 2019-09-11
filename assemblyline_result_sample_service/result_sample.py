import json
import os
import random
import tempfile

from assemblyline.common.dict_utils import flatten
from assemblyline.common.hexdump import hexdump

# DO NOT IMPORT IN YOUR SERVICE. These are just for creating randomized results.
from assemblyline.odm.randomizer import get_random_phrase, get_random_ip, get_random_host, get_random_tags

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

# DO NOT LIST HEURISTICS, BODY FORMAT and tag types LIKE THIS. This is again for the data randomizer
HEUR_LIST = ["AL_RESULTSAMPLE_1", "AL_RESULTSAMPLE_2", "AL_RESULTSAMPLE_3", "AL_RESULTSAMPLE_4"]
FORMAT_LIST = [BODY_FORMAT.TEXT, BODY_FORMAT.MEMORY_DUMP]


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
        #   This sample service always drop an embedded file that will generate random result
        #   We're making a check to see if we're scanning the embedded file.
        #   In a normal service this is not something you would do at all but since we are using this
        #   service in our unit test to test all features of our report generator, we have to do this
        if request.sha256 != 'd729ecfb2cf40bc4af8038dac609a57f57dbe6515d35357af973677d5e66417a':
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
            text_section.set_heuristic(random.choice(HEUR_LIST))
            # Make sure you add your section to the result
            result.add_section(text_section)

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
            section_color_map = ResultSection("Example of colormap result section", body_format=BODY_FORMAT.GRAPH_DATA,
                                              body=json.dumps(color_map_data))
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
            url_section.add_tag("network.domain", random_host)

            # You may also want to provide a list of url!
            #   Also, No need to provide a name, the url link will be displayed
            host1 = get_random_host()
            host2 = get_random_host()
            ip1 = get_random_ip()
            urls = [{"url": f"https://{host1}/"}, {"url": f"https://{host2}/"}, {"url": f"https://{ip1}/"}]
            url_sub_section = ResultSection('Example of a url section with multiple links', body_format=BODY_FORMAT.URL,
                                            body=json.dumps(urls))
            url_sub_section.set_heuristic(random.choice(HEUR_LIST))
            url_sub_section.add_tag("network.ip", ip1)
            url_sub_section.add_tag("network.domain", host1)
            url_sub_section.add_tag("network.domain", host2)
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
            memdump_section.set_heuristic(random.choice(HEUR_LIST))
            result.add_section(memdump_section)

            # ==================================================================
            # JSON section:
            #     Re-use the JSON editor we use for administration (https://github.com/josdejong/jsoneditor)
            #     to display a tree view of JSON results.
            #     NB: Use this sparingly! As a service developer you should do your best to include important
            #     results as their own result sections.
            #     The body argument must be a dictionary
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
            # Re-Submitting files to the system
            #     Adding extracted files will have them resubmitted to the system for analysis

            fd, temp_path = tempfile.mkstemp(dir=request.working_directory)
            with os.fdopen(fd, "wb") as myfile:
                myfile.write(data.encode())
            request.add_extracted(temp_path, "file.txt", "Extracted by some random magic!")

            # ==================================================================
            # Supplementary files
            #     Adding supplementary files will save them on the datastore for future
            #      reference but wont reprocess those files.
            fd, temp_path = tempfile.mkstemp(dir=request.working_directory)
            with os.fdopen(fd, "w") as myfile:
                myfile.write(json.dumps(urls))
            request.add_supplementary(temp_path, "urls.json", "These are urls as a JSON file")
            # like embedded files, you can add more then one supplementary files
            fd, temp_path = tempfile.mkstemp(dir=request.working_directory)
            with os.fdopen(fd, "w") as myfile:
                myfile.write(json.dumps(json_body))
            request.add_supplementary(temp_path, "json_body.json", "This is the json_body as a JSON file")

            # ==================================================================
            # Wrap-up:
            #     Save your result object back into the request
            request.result = result
        else:
            # Embedded file results...
            #   For the embedded file results we will completely randomize the results
            #     The content of those results do not matter since we've already showed you
            #     all the different result sections, tagging, heuristics and file upload functions
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
            section.set_heuristic(random.choice(HEUR_LIST))

        # Create random sub-sections
        if random.choice([False, False, True]):
            section.add_subsection(self._create_random_section())

        return section
