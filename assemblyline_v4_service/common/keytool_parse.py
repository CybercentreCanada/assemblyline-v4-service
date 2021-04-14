from re import split
from subprocess import Popen, PIPE
from assemblyline.common.str_utils import safe_str
from typing import List

class Certificate():
    def __init__(self):
        self.raw = ""
        self.issuer = ""
        self.owner = ""
        self.country = ""
        self.valid_from = ""
        self.valid_to = ""

def keytool_printcert(cert_path: str) -> None:
    """
    This function runs the 'keytool -printcert' command against a provided file

    :param cert_path: A path to a certificate
    :return: the string output of 'keytool -printcert' or None
    """
    stdout, _ = Popen(["keytool", "-printcert", "-file", cert_path],
                                stderr=PIPE, stdout=PIPE).communicate()
    stdout = safe_str(stdout)

    if stdout and "keytool error" not in stdout:
        return stdout

    return None

def certificate_chain_from_printcert(printcert: str) -> List[Certificate]:
    """
    This function parses the output of 'keytool -printcert' and creates a list of Certificate objects.
    The input to this function is the output of keytool_printcert

    :param printcert: the string output of 'keytool -printcert'
    :return: a list of the parsed out certificates. If only one certificate is present and not a chain, then the list will have one element.
    """
    certs: List[Certificate] = []

    for cert_str in split('Certificate\[\d+\]:', printcert): # split printcert output in case of certificate chain
        if cert_str == '':
            continue
        cert = Certificate()
        cert.raw = cert_str.strip()
        for line in cert_str.splitlines():
            if "Owner:" in line:
                cert.owner = line.split(": ", 1)[1]
                country = cert.owner.split("C=")
                if len(country) != 1:
                    cert.country = country[1]

            elif "Issuer:" in line:
                cert.issuer = line.split(": ", 1)[1]

            elif "Valid from:" in line:
                cert.valid_from = line.split(": ", 1)[1].split(" until:")[0]
                cert.valid_to = line.rsplit(": ", 1)[1]

        certs.append(cert)

    return certs