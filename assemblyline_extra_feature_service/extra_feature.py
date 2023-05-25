from pprint import pformat

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection


class ExtraFeature(ServiceBase):
    def __init__(self, config=None):
        super(ExtraFeature, self).__init__(config)

    def execute(self, request):
        result = Result()
        # ==================================================================
        # Tags generated from other services
        #
        # NOTE: To be able to use this, the service must set "uses_tags: true"
        #       in its manifest.
        tags = request.task.tags
        tag_section = ResultSection('Tags generated from other services', body_format=BODY_FORMAT.MEMORY_DUMP,
                                    body=pformat(tags, indent=2))
        result.add_section(tag_section)

        # ==================================================================
        # Metadata provided during submission
        #
        # NOTE: To be able to use this, the service must set "uses_metadata: true"
        #       in its manifest.
        metadata = request.task.metadata
        meta_section = ResultSection('Metadata provided during submission', body_format=BODY_FORMAT.MEMORY_DUMP,
                                     body=pformat(metadata, indent=2))
        result.add_section(meta_section)

        # ==================================================================
        # Temporary submission data provided:
        #   - During submission
        #   - By other services
        #
        # NOTE: To be able to use this, the service must set "uses_temp_submission_data: true"
        #       in its manifest.
        temp_submission_data = request.temp_submission_data
        temp_section = ResultSection('Temporary submission data', body_format=BODY_FORMAT.MEMORY_DUMP,
                                     body=pformat(temp_submission_data, indent=2))
        result.add_section(temp_section)

        request.result = result
