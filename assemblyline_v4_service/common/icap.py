import os
import socket

from assemblyline.common.str_utils import safe_str

ICAP_OK = b'ICAP/1.0 200 OK'


# noinspection PyBroadException
class IcapClient(object):
    """
    A limited Internet Content Adaptation Protocol client.

    Currently only supports RESPMOD as that is all that is required to interop
    with most ICAP based AV servers.
    """

    RESP_CHUNK_SIZE = 65565
    MAX_RETRY = 3

    def __init__(self, host, port, respmod_service="av/respmod", action="", timeout=30, number_of_retries=MAX_RETRY):
        self.host = host
        self.port = port
        self.service = respmod_service
        self.action = action
        self.socket = None
        self.timeout = timeout
        self.kill = False
        self.number_of_retries = number_of_retries
        self.successful_connection = False

    def scan_data(self, data, name=None):
        return self._do_respmod(name or 'filetoscan', data)

    def scan_local_file(self, filepath):
        filename = os.path.basename(filepath)
        with open(filepath, 'r') as f:
            data = f.read()
            return self.scan_data(data, filename)

    def options_respmod(self):
        request = f"OPTIONS icap://{self.host}:{self.port}/{self.service} ICAP/1.0\r\n\r\n"

        for i in range(self.number_of_retries):
            if self.kill:
                self.kill = False
                return
            try:
                if not self.socket:
                    self.socket = socket.create_connection((self.host, self.port), timeout=self.timeout)
                    self.successful_connection = True
                self.socket.sendall(request.encode())
                response = temp_resp = self.socket.recv(self.RESP_CHUNK_SIZE)
                while len(temp_resp) == self.RESP_CHUNK_SIZE:
                    temp_resp = self.socket.recv(self.RESP_CHUNK_SIZE)
                    response += temp_resp
                if not response or not response.startswith(ICAP_OK):
                    raise Exception(f"Unexpected OPTIONS response: {response}")
                return response.decode()
            except Exception:
                self.successful_connection = False
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.socket = None
                if i == (self.number_of_retries-1):
                    raise

        raise Exception("Icap server refused to respond.")

    @staticmethod
    def chunk_encode(data):
        chunk_size = 8160
        out = b""
        offset = 0
        while len(data) < offset * chunk_size:
            out += "1FEO\r\n"
            out += data[offset * chunk_size:(offset + 1) * chunk_size]
            out += "\r\n"
            offset += 1

        out += b"%X\r\n" % len(data[offset * chunk_size:])
        out += data[offset * chunk_size:]
        out += b"\r\n0\r\n\r\n"

        return out

    def _do_respmod(self, filename, data):
        encoded = self.chunk_encode(data)

        # ICAP RESPMOD req-hdr is the start of the original HTTP request.
        respmod_req_hdr = "GET /{FILENAME} HTTP/1.1\r\n\r\n".format(FILENAME=safe_str(filename))

        # ICAP RESPMOD res-hdr is the start of the HTTP response for above request.
        respmod_res_hdr = (
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n\r\n")

        res_hdr_offset = len(respmod_req_hdr)
        res_bdy_offset = len(respmod_res_hdr) + res_hdr_offset

        # The ICAP RESPMOD header. Note:
        # res-hdr offset should match the start of the GET request above.
        # res-body offset should match the start of the response above.

        respmod_icap_hdr = (
            f"RESPMOD icap://{self.host}:{self.port}/{self.service}{self.action} ICAP/1.0\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Allow: 204\r\n"
            f"Encapsulated: req-hdr=0, res-hdr={res_hdr_offset}, res-body={res_bdy_offset}\r\n\r\n"
        )

        serialized_request = b"%s%s%s%s" % (respmod_icap_hdr.encode(), respmod_req_hdr.encode(),
                                            respmod_res_hdr.encode(), encoded)

        for i in range(self.number_of_retries):
            if self.kill:
                self.kill = False
                return
            try:
                if not self.socket:
                    self.socket = socket.create_connection((self.host, self.port), timeout=self.timeout)
                    self.successful_connection = True
                self.socket.sendall(serialized_request)
                response = temp_resp = self.socket.recv(self.RESP_CHUNK_SIZE)
                while len(temp_resp) == self.RESP_CHUNK_SIZE:
                    temp_resp = self.socket.recv(self.RESP_CHUNK_SIZE)
                    response += temp_resp

                return response.decode()
            except Exception:
                self.successful_connection = False
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.socket = None
                if i == (self.number_of_retries-1):
                    raise

        raise Exception("Icap server refused to respond.")

    def close(self):
        self.kill = True
        try:
            self.socket.close()
        except Exception:
            pass
