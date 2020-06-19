from assemblyline_v4_service.common.result import Result, ResultSection
from assemblyline_v4_service.common.tag_reducer import REDUCE_MAP


def reduce(al_result: Result) -> Result:
    """
    This function goes through a result section recursively and try reduce the amount of
    produced tags based on a reducer set for each specific tags

    :param al_result: An Assemblyline result object
    :return: Reduced Assemblyline result object
    """
    for section in al_result.sections:
        _section_traverser(section)
    return al_result


def _section_traverser(section: ResultSection = None) -> ResultSection:
    """
    This function goes through each section and sends the tags to a function
    that will reduce specific tags

    :param section: An Assemblyline result section
    :return: Reduced Assemblyline result section
    """
    for subsection in section.subsections:
        _section_traverser(subsection)
    if section.tags:
        section.tags = _reduce_specific_tags(section.tags)
    return section


def _reduce_specific_tags(tags=None) -> {}:
    """
    This function is very much a work in progress. Currently the only tags that we
    feel the need to reduce are unique uris and uri paths
    :param tags: Dictionary of tag types and their values
    :return: Dictionary of tag types and their reduced values
    """
    if tags is None:
        tags = {}

    return {tag_type: REDUCE_MAP.get(tag_type, lambda x: x)(tag_values) for tag_type, tag_values in tags.items()}
