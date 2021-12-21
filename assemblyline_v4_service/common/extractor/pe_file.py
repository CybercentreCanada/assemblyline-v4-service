import re

from typing import List, Tuple

import pefile

EXEDOS_RE = rb'(?s)This program cannot be run in DOS mode'
EXEHEADER_RE = rb'(?s)MZ.{32,1024}PE\000\000'

def find_pe_files(data: bytes) -> List[Tuple[bytes, int, int]]:
    """
    Searches for any PE files within data

    Args:
        data: The data to search
    Returns:
        A list of found PE files
    """
    pe_files: List[Tuple[bytes, int, int]] = []
    offset = 0
    while offset < len(data):
        match = re.search(EXEHEADER_RE, data)
        if not match:
            return pe_files
        pe_data = data[offset:]
        if not re.search(EXEDOS_RE, pe_data):
            return pe_files
        try:
            pe = pefile.PE(data=pe_data)
            size = max(section.PointerToRawData + section.SizeOfRawData for section in pe.sections)
            if size == 0:
                return pe_files
            end = offset+size
            pe_files.append((data[offset:end], offset, end))
            offset=end
        except Exception:
            return pe_files
    return pe_files
