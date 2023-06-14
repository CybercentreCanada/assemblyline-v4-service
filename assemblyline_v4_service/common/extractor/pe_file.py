from multidecoder.analyzers.pe_file import find_pe_files as find_pe_hits
from typing import List

EXEDOS_RE = rb'(?s)This program cannot be run in DOS mode'
EXEHEADER_RE = rb'(?s)MZ.{32,1024}PE\000\000'


def find_pe_files(data: bytes) -> List[bytes]:
    """
    Searches for any PE files within data

    Args:
        data: The data to search
    Returns:
        A list of found PE files
    """
    return [pe.value for pe in find_pe_hits(data)]
