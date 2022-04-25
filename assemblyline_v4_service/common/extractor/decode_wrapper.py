from __future__ import annotations

from collections import defaultdict

from multidecoder.multidecoder import Multidecoder
from multidecoder.query import invert_tree


STATIC_MAP = {
    'network.domain': 'network.static.domain',
    'network.ip': 'network.static.ip',
    'network.url': 'network.static.uri'
}

DYNAMIC_MAP = {
    'network.domain': 'network.dynamic.domain',
    'network.ip': 'network.dynamic.ip',
    'network.url': 'network.dynamic.uri',
}

COMMON_MAP = {
    'network.email': 'network.email.address',
    'powershell.cmdlet': 'file.powershell.cmdlet',
    # blacklist
    'archive': 'file.string.blacklisted',
    'av.name': 'file.string.blacklisted',
    'cryptography': 'file.string.blacklisted',
    'debugger.device.name': 'file.string.blacklisted',
    'enable_content': 'file.string.blacklisted',
    'environment.windows': 'file.string.blacklisted',
    'event': 'file.string.blacklisted',
    'guid': 'file.string.blacklisted',
    'network.protocol': 'file.string.blacklisted',
    'network.string': 'file.string.blacklisted',
    'oid': 'file.string.blacklisted',
    'privilege': 'file.string.blacklisted',
    'ransomware.string': 'file.string.blacklisted',
    'sandbox.id': 'file.string.blacklisted',
    'security_identifier': 'file.string.blacklisted',
    'vba.name': 'file.string.blacklisted',
    'windows.registry': 'file.string.blacklisted'
}


class DecoderWrapper():
    def __init__(self) -> None:
        self.multidecoder = Multidecoder()
        self.map = COMMON_MAP
        for label in self.multidecoder.analyzers.values():
            if label.startswith('api'):
                self.map[label] = 'file.string.api'
            elif label.startswith('filename'):
                self.map[label] = 'file.name.extracted'

    def ioc_tags(self, data: bytes, dynamic=False) -> dict[str, set[bytes]]:
        self.map.update(DYNAMIC_MAP) if dynamic else self.map.update(STATIC_MAP)
        tags: dict[str, set[bytes]] = defaultdict(set)
        tree = self.multidecoder.scan(data)
        nodes = invert_tree(tree)
        for node in nodes:
            if node.type in self.map:
                tags[self.map[node.type]].add(node.value)
        return tags
