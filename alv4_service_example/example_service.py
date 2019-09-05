import json
import os
import random
import tempfile

from assemblyline.common.hexdump import hexdump
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT


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
        # Executed a request:
        #   Every time your service receives a new file to scan, the execute function is called
        #   This is where you should execute your processing code.
        #   For the purpose of this exemple, we will only generate results ...

        # run your code here...


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
        text_section.add_line("You can add line by line!")
        text_section.add_lines(["Or", "Multiple lines", "Inside a list!"])
        # if the section needs to affect the score of the file you need to set a heuristics
        text_section.set_heuristic("AL_RESULTSAMPLE_1")
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
        #     Generate a list of clickable urls using a json encoded format
        url_section = ResultSection('Example of a simple url section', body_format=BODY_FORMAT.URL,
            body=json.dumps({"name": "Google", "url": "https://www.google.com/"}))

        # Since urls are very important features we can tag those features in the system so they are easy to find
        #   Tags are defined by a type and a value
        url_section.add_tag("network.domain", "google.com")

        # You may also want to provide a list of url! Also, No need to provide a name, the url link will be displayed
        urls = [{"url": "https://google.com/"}, {"url": "https://google.ca/"}, {"url": "https://microsoft.com/"}]
        url_sub_section = ResultSection('Example of a url section with multiple links', body_format=BODY_FORMAT.URL,
            body=json.dumps(urls))
        url_sub_section.set_heuristic("AL_RESULTSAMPLE_2")
        url_sub_section.add_tag("network.domain", "google.com")
        url_sub_section.add_tag("network.domain", "google.ca")
        url_sub_section.add_tag("network.domain", "microsoft.com")
        # Since url_sub_section is a sub-section of url_section
        # we will add it as a sub-section of url_section not to the result itself
        url_section.add_subsection(url_sub_section)
        result.add_section(url_section)

        # ==================================================================
        # Memory dump section: BODY_FORMAT.MEMORY_DUMP
        #     Dump whatever string content you have into a <pre/> html tag so you can do your own formatting
        data = hexdump(b"This is some random text that we will format as an hexdump and you'll see "
                       b"that the hexdump formatting will be preserved by the memory dump section!")
        memdump_section = ResultSection('Example of a memory dump section', body_format=BODY_FORMAT.MEMORY_DUMP,
            body=data)
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
        json_section.set_heuristic("AL_RESULTSAMPLE_3")
        result.add_section(json_section)

        # ==================================================================
        # Re-Submitting files to the system
        #     Adding extracted files will have them resubmitted to the system for analysis
        if request.sha256 != 'd729ecfb2cf40bc4af8038dac609a57f57dbe6515d35357af973677d5e66417a':
            # This IF just prevents resubmitting the same file in a loop for this exemple...
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
        request.add_supplementary(temp_path, "urls.json", "These are urls as a JSON")

        # ==================================================================
        # Wrap-up:
        #     Save your result object back into the request
        request.result = result
