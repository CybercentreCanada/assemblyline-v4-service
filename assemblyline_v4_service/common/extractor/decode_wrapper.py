from __future__ import annotations

import hashlib
import os

from collections import defaultdict
from typing import Any, Optional

from multidecoder.multidecoder import Multidecoder
from multidecoder.query import invert_tree


STATIC_TAG_MAP = {
    'network.domain': 'network.static.domain',
    'network.ip': 'network.static.ip',
    'network.url': 'network.static.uri'
}

DYNAMIC_TAG_MAP = {
    'network.domain': 'network.dynamic.domain',
    'network.ip': 'network.dynamic.ip',
    'network.url': 'network.dynamic.uri',
}

TAG_MAP = {
    'network.email': 'network.email.address',
    'powershell.cmdlet': 'file.powershell.cmdlet',
}

BLACKLIST = {
    'archive',
    'av.name',
    'cryptography',
    'debugger.device.name',
    'enable_content',
    'environment.windows',
    'event',
    'guid',
    'network.protocol',
    'network.string',
    'oid',
    'privilege',
    'ransomware.string',
    'sandbox.id',
    'security_identifier',
    'vba.name',
    'windows.registry'
}


def map_tag_type(tag_type: str, dynamic=False) -> Optional[str]:
    if tag_type in TAG_MAP:
        return TAG_MAP[tag_type]
    if tag_type in STATIC_TAG_MAP:
        return DYNAMIC_TAG_MAP[tag_type] if dynamic else STATIC_TAG_MAP[tag_type]
    if tag_type in BLACKLIST:
        return 'file.string.blacklisted'
    if tag_type.startswith('api'):
        return 'file.string.api'
    if tag_type.startswith('filename'):
        return 'file.name.extracted'
    return None


def get_tree_tags(tree: list[dict[str, Any]], dynamic=False) -> dict[str, set[bytes]]:
    tags: dict[str, set[bytes]] = defaultdict(set)
    nodes = invert_tree(tree)
    for node in nodes:
        tag_type = map_tag_type(node.type, dynamic)
        if tag_type:
            tags[tag_type].add(node.value)
    return tags


def extract_files(tree: list[dict[str, Any]], min_size, working_directory) -> list[str]:
    seen_files = set()
    files: list[str] = []
    nodes = invert_tree(tree)
    for node in nodes:
        if len(node.value) < min_size or node.value in seen_files:
            continue
        seen_files.add(node.value)
        if node.type == 'pe_file':
            ext = '.exe'
        elif node.obfuscation.startswith('decoded.base64'):
            ext = '_b64'  # technically .b64 is for still encoded files
        elif node.obfuscation.startswith('decoded.hexadecimal'):
            ext = '_hex'
        else:
            continue
        file_hash = hashlib.sha256(node.value).hexdigest()
        file_name = file_hash[:8] + ext
        file_path = os.path.join(working_directory, file_name)
        with open(file_path, 'wb') as f:
            f.write(node.value)
        files.append(file_path)
    return files


class DecoderWrapper():
    def __init__(self) -> None:
        self.multidecoder = Multidecoder()

    def ioc_tags(self, data: bytes, dynamic=False) -> dict[str, set[bytes]]:
        tree = self.multidecoder.scan(data)
        return get_tree_tags(tree, dynamic)
