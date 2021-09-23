"""
Modified version of patterns.py found here:
https://github.com/decalage2/balbuzard

Info:
balbuzard patterns - v0.07 2014-02-13 Philippe Lagadec
For more info and updates: http://www.decalage.info/balbuzard
"""

# LICENSE:
#
# balbuzard is copyright (c) 2007-2014, Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import re
from os import path
from xml.etree import ElementTree

from fuzzywuzzy import process

from assemblyline_v4_service.common.balbuzard.balbuzard import Pattern, Pattern_re


def get_xml_strings():

    pest_minlen = 6

    api = {}
    blacklist = {}
    powershell = {}

    with open(path.join(path.dirname(__file__), "../pestudio/xml/strings.xml"), 'rt') as f:
        tree = ElementTree.parse(f)

    for st in tree.findall('.//agent'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('agent', set()).add(st.text)
    for st in tree.findall('.//av'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('av', set()).add(st.text)
    for st in tree.findall('.//event'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('event', set()).add(st.text)
    for st in tree.findall('.//guid'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('guid', set()).add(st.text)
    for st in tree.findall('.//insult'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('insult', set()).add(st.text)
    for st in tree.findall('.//key'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('key', set()).add(st.text)
    for st in tree.findall('.//oid'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('oid', set()).add(st.text)
    for st in tree.findall('.//os'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('os', set()).add(st.text)
    for st in tree.findall('.//priv'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('priv', set()).add(st.text)
    for st in tree.findall('.//product'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('product', set()).add(st.text)
    for st in tree.findall('.//protocol'):
        blacklist.setdefault('protocol', set()).add(st.text)
    for st in tree.findall('.//reg'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('reg', set()).add(st.text)
    for st in tree.findall('.//sid'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('sid', set()).add(st.text)
    for st in tree.findall('.//string'):
        if len(st.text) > pest_minlen:
            blacklist.setdefault('string', set()).add(st.text)
    # Powershell indicator strings
    for st in tree.findall('.//powershell'):
        if len(st.text) > pest_minlen:
            powershell.setdefault('powershell', set()).add(st.text)

    # Adding Popular API
    with open(path.join(path.dirname(__file__), '../pestudio/xml/functions.xml'), 'rt') as f:
        tree = ElementTree.parse(f)

    for st in tree.findall(".//fct"):
        if st.text is not None:
            if len(st.text) > pest_minlen and st.text is not None:
                api.setdefault('fct', set()).add(st.text.split('::', 1)[0])
    for st in tree.findall(".//lib"):
        if st.attrib['name'] is not None:
            if len(st.attrib['name']) > pest_minlen:
                api.setdefault('lib', set()).add(st.attrib['name'])
    for st in tree.findall('.//topapi'):
        if st.text is not None:
            if len(st.text) > pest_minlen:
                api.setdefault('topapi', set()).add(st.text)

    return api, blacklist, powershell


class PatternMatch(object):

    # Curated list to avoid false positives.
    TDLS = {b'ac', b'aco', b'ad', b'adac', b'ads', b'ae', b'aeg', b'aero', b'af', b'afl', b'ag', b'agakhan', b'ai',
            b'aig', b'akdn', b'al', b'am', b'amica', b'anz', b'ao', b'apple', b'aq', b'ar', b'army', b'arpa', b'at',
            b'au', b'aw', b'aws', b'ax', b'axa', b'az', b'ba', b'baidu', b'bbc', b'bbva', b'bcg', b'bcn', b'bd', b'be',
            b'bf', b'bg', b'bh', b'bharti', b'bi', b'bing', b'biz', b'bj', b'blog', b'bm', b'bms', b'bn', b'bnl', b'bo',
            b'bom', b'bot', b'br', b'bs', b'bt', b'bv', b'bw', b'by', b'bz', b'bzh', b'ca', b'cba', b'cbn', b'cbre',
            b'ceb', b'cf', b'cfa', b'cfd', b'cg', b'ch', b'ci', b'ck', b'cl', b'cm', b'cn', b'co', b'com', b'cr',
            b'crs', b'csc', b'cu', b'cv', b'cw', b'cx', b'cy', b'cz', b'dclk', b'dds', b'de', b'dev', b'dhl', b'dj',
            b'dk', b'dm', b'dnp', b'do', b'docs', b'doha', b'domains', b'download', b'drive', b'dtv', b'dubai', b'dvag',
            b'dz', b'ec', b'edu', b'er', b'erni', b'es', b'esq', b'et', b'eu', b'eurovision', b'eus', b'fi', b'fj',
            b'fk', b'flickr', b'flir', b'flsmidth', b'fly', b'fm', b'fo', b'foo', b'fr', b'frl', b'ftr', b'ga', b'gb',
            b'gbiz', b'gd', b'gdn', b'ge', b'gea', b'gl', b'gle', b'gm', b'gmail', b'gmbh', b'gmo', b'gmx', b'gn',
            b'goog', b'google', b'gop', b'got', b'gov', b'gp', b'gq', b'gr', b'gs', b'gt', b'gu', b'guru', b'gw', b'gy',
            b'hk', b'hkt', b'hm', b'hn', b'host', b'hotmail', b'hr', b'ht', b'htc', b'hu', b'icu', b'id', b'ie',
            b'ifm', b'iinet', b'ikano', b'il', b'im', b'imamat', b'imdb', b'immo', b'immobilien', b'in', b'info',
            b'ing', b'ink', b'int', b'io', b'ipiranga', b'iq', b'ir', b'is', b'ist', b'istanbul', b'it', b'itau',
            b'itv', b'iwc', b'jaguar', b'jcb', b'jcp', b'je', b'jlc', b'jll', b'jm', b'jmp', b'jnj', b'jo', b'jot',
            b'jp', b'ke', b'kfh', b'kg', b'kh', b'ki', b'kia', b'kindle', b'km', b'kn', b'kp', b'kpmg', b'kpn', b'kr',
            b'krd', b'kw', b'ky', b'kyoto', b'kz', b'la', b'lat', b'lb', b'lc', b'lds', b'li', b'link', b'lk', b'lol',
            b'lr', b'ls', b'lt', b'ltd', b'ltda', b'lu', b'lv', b'ly', b'ma', b'madrid', b'mba', b'mc', b'md', b'me',
            b'med', b'meme', b'meo', b'mg', b'mh', b'microsoft', b'mil', b'mk', b'ml', b'mlb', b'mls', b'mma',
            b'mn', b'mo', b'mobi', b'mobily', b'mov', b'mp', b'mq', b'mr', b'ms', b'mt', b'mtn', b'mtpc', b'mtr',
            b'mu', b'mv', b'mw', b'mx', b'my', b'mz', b'na', b'navy', b'nc', b'ne', b'nec', b'net', b'netbank',
            b'neustar', b'nexus', b'nf', b'ng', b'ngo', b'nhk', b'ni', b'nico', b'nl', b'nowruz', b'nowtv', b'np',
            b'nr', b'nra', b'nrw', b'ntt', b'nu', b'nyc', b'nz', b'obi', b'ollo', b'om', b'ong', b'onl', b'org', b'ott',
            b'ovh', b'pa', b'pccw', b'pe', b'pet', b'pf', b'pg', b'ph', b'pid', b'pin', b'ping', b'pk', b'pl', b'pm',
            b'pn', b'pnc', b'pohl', b'porn', b'post', b'pr', b'pro', b'prod', b'ps', b'pt', b'pub', b'pw', b'pwc',
            b'py', b'qa', b'qpon', b'quebec', b're', b'ren', b'rio', b'ro', b'rocher', b'rs', b'rsvp', b'ru', b'ruhr',
            b'rw', b'rwe', b'ryukyu', b'sa', b'sap', b'sapo', b'sarl', b'sas', b'saxo', b'sb', b'sbi', b'sbs',
            b'sc', b'sca', b'scb', b'sd', b'se', b'sew', b'sex', b'sfr', b'sg', b'sh', b'si', b'sina', b'site',
            b'sj', b'sk', b'skype', b'sl', b'sm', b'sn', b'sncf', b'so', b'sr', b'srl', b'st', b'stc', b'stcgroup',
            b'su', b'sv', b'sx', b'sy', b'sydney', b'symantec', b'systems', b'sz', b'tab',
            b'taipei', b'taobao', b'tc', b'tci', b'td', b'tdk', b'tel', b'teva', b'tf', b'tg', b'th', b'thd', b'tj',
            b'tk', b'tl', b'tm', b'tmall', b'tn', b'to', b'tokyo', b'tr', b'trv', b'tt', b'tube', b'tui', b'tunes',
            b'tushu', b'tv', b'tw', b'tz', b'ua', b'ubs', b'ug', b'uk', b'uno', b'uol', b'ups', b'us', b'uy', b'uz',
            b'va', b'vc', b've', b'vet', b'vg', b'vi', b'vig', b'vin', b'vip', b'vista', b'vistaprint', b'vn',
            b'vu', b'wed', b'weibo', b'weir', b'wf', b'whoswho', b'wien', b'wiki', b'win', b'windows', b'wme', b'ws',
            b'wtc', b'wtf', b'xbox', b'xerox', b'xihuan', b'xin', b'xn--11b4c3d', b'xn--1ck2e1b',
            b'xn--1qqw23a', b'xn--30rr7y', b'xn--3bst00m', b'xn--3ds443g', b'xn--3e0b707e', b'xn--3pxu8k',
            b'xn--42c2d9a', b'xn--45brj9c', b'xn--45q11c', b'xn--4gbrim', b'xn--55qw42g', b'xn--55qx5d',
            b'xn--5su34j936bgsg', b'xn--5tzm5g', b'xn--6frz82g', b'xn--6qq986b3xl', b'xn--80adxhks',
            b'xn--80ao21a', b'xn--80asehdb', b'xn--80aswg', b'xn--8y0a063a', b'xn--90a3ac', b'xn--90ae',
            b'xn--90ais', b'xn--9dbq2a', b'xn--9et52u', b'xn--9krt00a', b'xn--b4w605ferd', b'xn--bck1b9a5dre4c',
            b'xn--c1avg', b'xn--c2br7g', b'xn--cck2b3b', b'xn--cg4bki', b'xn--clchc0ea0b2g2a9gcd',
            b'xn--czr694b', b'xn--czrs0t', b'xn--czru2d', b'xn--d1acj3b', b'xn--d1alf', b'xn--e1a4c',
            b'xn--eckvdtc9d', b'xn--efvy88h', b'xn--estv75g', b'xn--fct429k', b'xn--fhbei', b'xn--fiq228c5hs',
            b'xn--fiq64b', b'xn--fiqs8s', b'xn--fiqz9s', b'xn--fjq720a', b'xn--flw351e', b'xn--fpcrj9c3d',
            b'xn--fzc2c9e2c', b'xn--fzys8d69uvgm', b'xn--g2xx48c', b'xn--gckr3f0f', b'xn--gecrj9c',
            b'xn--h2brj9c', b'xn--hxt814e', b'xn--i1b6b1a6a2e', b'xn--imr513n', b'xn--io0a7i', b'xn--j1aef',
            b'xn--j1amh', b'xn--j6w193g', b'xn--jlq61u9w7b', b'xn--jvr189m', b'xn--kcrx77d1x4a', b'xn--kprw13d',
            b'xn--kpry57d', b'xn--kpu716f', b'xn--kput3i', b'xn--l1acc', b'xn--lgbbat1ad8j', b'xn--mgb9awbf',
            b'xn--mgba3a3ejt', b'xn--mgba3a4f16a', b'xn--mgba7c0bbn0a', b'xn--mgbaam7a8h', b'xn--mgbab2bd',
            b'xn--mgbayh7gpa', b'xn--mgbb9fbpob', b'xn--mgbbh1a71e', b'xn--mgbc0a9azcg', b'xn--mgbca7dzdo',
            b'xn--mgberp4a5d4ar', b'xn--mgbpl2fh', b'xn--mgbt3dhd', b'xn--mgbtx2b', b'xn--mgbx4cd0ab',
            b'xn--mix891f', b'xn--mk1bu44c', b'xn--mxtq1m', b'xn--ngbc5azd', b'xn--ngbe9e0a', b'xn--node',
            b'xn--nqv7f', b'xn--nqv7fs00ema', b'xn--nyqy26a', b'xn--o3cw4h', b'xn--ogbpf8fl', b'xn--p1acf',
            b'xn--p1ai', b'xn--pbt977c', b'xn--pgbs0dh', b'xn--pssy2u', b'xn--q9jyb4c', b'xn--qcka1pmc',
            b'xn--qxam', b'xn--rhqv96g', b'xn--rovu88b', b'xn--s9brj9c', b'xn--ses554g', b'xn--t60b56a',
            b'xn--tckwe', b'xn--unup4y', b'xn--vermgensberater-ctb', b'xn--vermgensberatung-pwb', b'xn--vhquv',
            b'xn--vuq861b', b'xn--w4r85el8fhu5dnra', b'xn--w4rs40l', b'xn--wgbh1c', b'xn--wgbl6a',
            b'xn--xhq521b', b'xn--xkc2al3hye2a', b'xn--xkc2dl3a5ee0h', b'xn--y9a3aq', b'xn--yfro4i67o',
            b'xn--ygbi2ammx', b'xn--zfr164b', b'xperia', b'xyz', b'yahoo', b'yamaxun',
            b'yandex', b'ye', b'yokohama', b'you', b'youtube', b'yt', b'yun', b'za', b'zappos',
            b'zara', b'zero', b'zippo', b'zm', b'zone', b'zuerich', b'zw'}

# --- PEStudio Patterns ------------------------------------------------------------------------------------------------

    PEST_API, PEST_BLACKLIST, PEST_POWERSHELL = get_xml_strings()

# --- Regex Patterns ---------------------------------------------------------------------------------------------------

    PAT_DOMAIN = rb'(?i)\b(?:[A-Z0-9-]+\.)+(?:XN--[A-Z0-9]{4,18}|[A-Z]{2,12})\b'
    PAT_FILECOM = rb'(?i)(?:\b[a-z]?[:]?[- _A-Z0-9.\\~]{0,75}[%]?' \
                  rb'(?:ALLUSERPROFILE|APPDATA|commonappdata|CommonProgramFiles|HOMEPATH|LOCALAPPDATA|' \
                  rb'ProgramData|ProgramFiles|PUBLIC|SystemDrive|SystemRoot|\\TEMP|USERPROFILE|' \
                  rb'windir|system32|syswow64|\\user)[%]?\\[-_A-Z0-9\.\\]{1,200}\b|' \
                  rb'/home/[-_A-Z0-9\./]{0,50}|/usr/local[-_A-Z0-9\./]{0,50}|/usr/bin[-_A-Z0-9\./]{0,50}|' \
                  rb'/var/log[-_A-Z0-9\./]{0,50}|/etc/(?:shadow|group|passwd))'
    PAT_FILEEXT = rb'(?i)\b[a-z]?[:]?[- _A-Z0-9.\\~]{0,200}\w\.' \
                  rb'(?:7Z|APK|APP|BAT|BIN|CLASS|CMD|DAT|DOC|DOCX|DLL|EML|EXE|JAR|JPEG|JPG|JS|JSE|LNK|LOG|MSI|' \
                  rb'OSX|PAF|PDF|PNG|PPT|PPTX|PS1|RAR|RTF|SCR|SWF|SYS|[T]?BZ[2]?|TXT|TMP|VBE|VBS|WSF|WSH|XLS' \
                  rb'|XLSX|ZIP)\b'
    PAT_FILEPDB = rb'(?i)\b[-_A-Z0-9.\\]{0,200}\w\.PDB\b'
    PAT_EMAIL = rb'(?i)\b[A-Z0-9._%+-]{3,}@(?:[A-Z0-9-]+\.)+(?:XN--[A-Z0-9]{4,18}|[A-Z]{2,12})\b'
    PAT_IP = rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    PAT_REGIS = rb'(?i)\b[- _A-Z0-9.\\]{0,25}' \
                rb'(?:controlset001|controlset002|currentcontrolset|currentversion|HKCC|HKCR|HKCU|HKDD|' \
                rb'hkey_classes_root|hkey_current_config|hkey_current_user|hkey_dyn_data|hkey_local_machine|' \
                rb'HKLM|hkey_performance_data|hkey_users|HKPD|internet settings|\\sam|\\software|\\system|' \
                rb'\\userinit)' \
                rb'\\[-_A-Z0-9.\\ ]{1,200}\b'
    PAT_URL = rb'(?i)(?:ftp|http|https)://' \
              rb'[A-Z0-9.-]{1,}\.(?:XN--[A-Z0-9]{4,18}|[a-z]{2,12}|[0-9]{1,3})' \
              rb'(?::[0-9]{1,5})?' \
              rb'(?:/[A-Z0-9/\-\.&%\$#=~\?_+]{3,200}){0,1}'
    PAT_ANYHTTP = rb'(?i)http://' \
                  rb'[A-Z0-9.-]{6,}\.' \
                  rb'(?:XN--[A-Z0-9]{4,18}|[a-z]{2,12}|[0-9]{1,3})' \
                  rb'(?::[0-9]{1,5})?' \
                  rb'/[A-Z0-9/\-\.&%\$#=~\?_+]{5,}[\r\n]*'
    PAT_ANYHTTPS = rb'(?i)https://' \
                   rb'[A-Z0-9.-]{6,}\.' \
                   rb'(?:XN--[A-Z0-9]{4,18}|[a-z]{2,12}|[0-9]{1,3})' \
                   rb'(?::[0-9]{1,5})?' \
                   rb'/[A-Z0-9/\-\.&%\$#=~\?_+]{5,}[\r\n]*'
    PAT_ANYFTP = rb'(?i)ftp://' \
                 rb'[A-Z0-9.-]{6,}\.' \
                 rb'(?:XN--[A-Z0-9]{4,18}|[a-z]{2,12}|[0-9]{1,3})' \
                 rb'(?::[0-9]{1,5})?' \
                 rb'/[A-Z0-9/\-\.&%\$#=~\?_+]{5,}[\r\n]*'
    PAT_URI_NO_PROTOCOL = rb'(?:(?:(?:[A-Za-z]*:)?//)?' \
                          rb'(?:[^"\']\S+(?::\S*)?@)?' \
                          rb'(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}' \
                          rb'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' \
                          rb'|(?:(?:[A-Za-z0-9\\u00a1-\\uffff][A-Za-z0-9\\u00a1-\\uffff_-]{0,62})?' \
                          rb'[A-Za-z0-9\\u00a1-\\uffff]\.)+(?:xn--)?' \
                          rb'(?:[A-Za-z0-9\\u00a1-\\uffff]{2,}\.?))' \
                          rb'(?::\d{2,5})?)' \
                          rb'(?:[/?#=&][a-zA-Z0-9.\-_~\$\.\+\!\*\'\(\)\,]+)*'

    PAT_EXEDOS = rb'This program cannot be run in DOS mode'
    PAT_EXEHEADER = rb'(?s)MZ.{32,1024}PE\000\000'

# --- Find Match for IOC Regex, Return Dictionary: {[AL Tag Type:(Match Values)]} --------------------------------------

    def ioc_match(self, value, bogon_ip=None, just_network=None):
        # NOTES:
        # '(?i)' makes a regex case-insensitive
        # \b matches a word boundary, it can help speeding up regex search and avoiding some false positives.
        # See http://www.regular-expressions.info/wordboundaries.html
        value_extract = {}
        # ------------------------------------------------------------------------------
        # IP ADDRESSES
        # Pattern_re("IP addresses", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", weight=10),
        # Here I use \b to make sure there is no other digit around and to speedup search
        # print("ips")
        find_ip = re.findall(self.PAT_IP, value)
        if len(find_ip) > 0:
            longeststring = max(find_ip, key=len)
            if len(longeststring) == len(value):
                not_filtered = self.ipv4_filter(value, bogon=bogon_ip)
                if not_filtered:
                    value_extract.setdefault('network.static.ip', set()).add(value)
                # If the complete value matches the IP regex, not interested in other regex values
                return value_extract
            if len(find_ip) == 1:
                for val in find_ip:
                    not_filtered = self.ipv4_filter(val, bogon=bogon_ip)
                    if not_filtered:
                        value_extract.setdefault('network.static.ip', set()).add(val)
            else:
                like_ls = process.extract(str(longeststring), find_ip, limit=50)
                final_values = list(filter(lambda ls: ls[1] < 99, like_ls))
                final_values.append((longeststring, 100))
                for val in final_values:
                    not_filtered = self.ipv4_filter(val[0], bogon=bogon_ip)
                    if not_filtered:
                        value_extract.setdefault('network.static.ip', set()).add(val[0])
        # ------------------------------------------------------------------------------
        # URLs
        # print("urls")
        find_url = re.findall(self.PAT_URL, value)
        if len(find_url) > 0:
            ret = False
            longeststring = max(find_url, key=len)
            if len(longeststring) == len(value):
                ret = True
                final_values = [(value, 100)]
            elif len(find_url) == 1:
                final_values = [(find_url[0], 100)]
            else:
                like_ls = process.extract(str(longeststring), find_url, limit=50)
                final_values = list(filter(lambda ls: ls[1] < 95, like_ls))
                final_values.append((longeststring, 100))

            for val in final_values:
                value_extract.setdefault('network.static.uri', set()).add(val[0])

                # Extract domain from URL
                find_domain = re.findall(self.PAT_DOMAIN, val[0])
                if len(find_domain) != 0:
                    longeststring = max(find_domain, key=len)
                    not_filtered = self.domain_filter(longeststring)
                    if not_filtered:
                        value_extract.setdefault('network.static.domain', set()).add(longeststring)
            if ret:
                return value_extract
        # ------------------------------------------------------------------------------
        # E-MAIL ADDRESSES
        # r'(?i)\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+(?:[A-Z]{2}|com|org|net|edu|gov|mil|int|biz|info|mobi|name|aero|asia|jobs|museum)\b',
        # changed to catch all current TLDs registered at IANA (in combination with filter function):
        # TLD = either only chars from 2 to 12, or 'XN--' followed by up to 18 chars and digits
        # print("emails")
        find_email = re.findall(self.PAT_EMAIL, value)
        if len(find_email) > 0:
            longeststring = max(find_email, key=len)
            if len(longeststring) == len(value):
                not_filtered = self.email_filter(value)
                if not_filtered:
                    value_extract.setdefault('network.email.address', set()).add(value)
                    return value_extract
            if len(find_email) == 1:
                for val in find_email:
                    not_filtered = self.email_filter(val)
                    if not_filtered:
                        value_extract.setdefault('network.email.address', set()).add(val)
            else:
                like_ls = process.extract(str(longeststring), find_email, limit=50)
                final_values = list(filter(lambda ls: ls[1] < 95, like_ls))
                final_values.append((longeststring, 100))
                for val in final_values:
                    not_filtered = self.email_filter(val[0])
                    if not_filtered:
                        value_extract.setdefault('network.email.address', set()).add(val[0])
        # ------------------------------------------------------------------------------
        # DOMAIN NAMES
        # Old: r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)'
        # Below is taken from email regex above
        # print("domains")
        find_domain = re.findall(self.PAT_DOMAIN, value)
        if len(find_domain) > 0 and len(max(find_domain, key=len)) > 11:
            longeststring = max(find_domain, key=len)
            if len(longeststring) == len(value):
                not_filtered = self.domain_filter(value)
                if not_filtered:
                    value_extract.setdefault('network.static.domain', set()).add(value)
                    return value_extract
            if len(find_domain) == 1:
                for val in find_domain:
                    not_filtered = self.domain_filter(val)
                    if not_filtered:
                        value_extract.setdefault('network.static.domain', set()).add(val)
            else:
                like_ls = process.extract(str(longeststring), find_domain, limit=50)
                final_values = list(filter(lambda ls: ls[1] < 95, like_ls))
                final_values.append((longeststring, 100))
                for val in final_values:
                    not_filtered = self.domain_filter(val[0])
                    if not_filtered:
                        value_extract.setdefault('network.static.domain', set()).add(val[0])

        if just_network:
            return value_extract

        # ------------------------------------------------------------------------------
        # FILENAMES
        # Check length
        # Ends with extension of interest or contains strings of interest
        # print("files")
        filefind_pdb = re.findall(self.PAT_FILEPDB, value)
        if len(filefind_pdb) > 0:
            if len(max(filefind_pdb, key=len)) > 6:
                longeststring = max(filefind_pdb, key=len)
                if len(longeststring) == len(value):
                    value_extract.setdefault('file.pe.pdb_filename', set()).add(value)
                    return value_extract
                if len(filefind_pdb) == 1:
                    for val in filefind_pdb:
                        value_extract.setdefault('file.pe.pdb_filename', set()).add(val)
                else:
                    like_ls = process.extract(str(longeststring), filefind_pdb, limit=50)
                    final_values = list(filter(lambda ls: ls[1] < 95, like_ls))
                    final_values.append((longeststring, 100))
                    for val in final_values:
                        value_extract.setdefault('file.pe.pdb_filename', set()).add(val[0])
        filefind_ext = re.findall(self.PAT_FILEEXT, value)
        if len(filefind_ext) > 0:
            if len(max(filefind_ext, key=len)) > 6:
                longeststring = max(filefind_ext, key=len)
                if len(longeststring) == len(value):
                    value_extract.setdefault('file.name.extracted', set()).add(value)
                    return value_extract
                if len(filefind_ext) == 1:
                    for val in filefind_ext:
                        value_extract.setdefault('file.name.extracted', set()).add(val)
                else:
                    like_ls = process.extract(str(longeststring), filefind_ext, limit=50)
                    final_values = list(filter(lambda ls: ls[1] < 95, like_ls))
                    final_values.append((longeststring, 100))
                    for val in final_values:
                        value_extract.setdefault('file.name.extracted', set()).add(val[0])
        filefind_com = re.findall(self.PAT_FILECOM, value)
        if len(filefind_com) > 0 and len(max(filefind_com, key=len)) > 6:
            longeststring = max(filefind_com, key=len)
            if len(longeststring) == len(value):
                value_extract.setdefault('file.name.extracted', set()).add(value)
                return value_extract
            if len(filefind_com) == 1:
                for val in filefind_com:
                    value_extract.setdefault('file.name.extracted', set()).add(val)
            else:
                like_ls = process.extract(str(longeststring), filefind_com, limit=50)
                final_values = list(filter(lambda ls: ls[1] < 95, like_ls))
                final_values.append((longeststring, 100))
                for val in final_values:
                    value_extract.setdefault('file.name.extracted', set()).add(val[0])
        # ------------------------------------------------------------------------------
        # REGISTRYKEYS
        # Looks for alpha numeric characters seperated by at least two sets of '\'s
        # print("reg")
        regfind = re.findall(self.PAT_REGIS, value)
        if len(regfind) > 0 and len(max(regfind, key=len)) > 15:
            longeststring = max(regfind, key=len)
            if len(longeststring) == len(value):
                value_extract.setdefault('dynamic.registry_key', set()).add(value)
                return value_extract
            if len(regfind) == 1:
                for val in regfind:
                    value_extract.setdefault('dynamic.registry_key', set()).add(val)
            else:
                like_ls = process.extract(str(longeststring), regfind, limit=50)
                final_values = list(filter(lambda ls: ls[1] < 90, like_ls))
                final_values.append((longeststring, 100))
                for val in final_values:
                    value_extract.setdefault('dynamic.registry_key', set()).add(val[0])
        # ------------------------------------------------------------------------------
        # PEStudio Blacklist
        # Flags strings from PEStudio's Blacklist
        final_values = []
        for k, i in self.PEST_BLACKLIST.items():
            for e in i:
                val = bytes(e, 'utf8')
                if val in value:
                    final_values.append(val)
        if len(final_values) > 0:
            value_extract['file.string.blacklisted'] = set()
        for val in final_values:
            value_extract['file.string.blacklisted'].add(val)
        # -----------------------------------------------------------------------------
        # Function/Library Strings
        # Win API strings from PEStudio's Blacklist
        final_values = []
        for k, i in self.PEST_API.items():
            for e in i:
                val = bytes(e, 'utf8')
                if val in value:
                    final_values.append(val)
        if len(final_values) > 0:
            value_extract['file.string.api'] = set()
        for val in final_values:
            value_extract['file.string.api'].add(val)
        # -----------------------------------------------------------------------------
        # Powershell Strings
        # Powershell Cmdlets added to PEStudio's strings.xml list
        final_values = []
        for k, i in self.PEST_POWERSHELL.items():
            for e in i:
                val = bytes(e, 'utf8')
                if val in value:
                    final_values.append(val)
        if len(final_values) > 0:
            value_extract['file.powershell.cmdlet'] = set()
        for val in final_values:
            value_extract['file.powershell.cmdlet'].add(val)

        return value_extract

# --- Filters ----------------------------------------------------------------------------------------------------------

    @staticmethod
    def ipv4_filter(value, bogon=None, **_):
        """
        IPv4 address filter:
        - check if string length is >7 (e.g. not just 4 digits and 3 dots)
        - check if not in list of bogon IP addresses
        return True if OK, False otherwise.
        """
        ip = value

        # 0.0.0.0 255.0.0.0e
        # > 255
        if ip.startswith(b'0'):
            return False
        for x in ip.split(b'.'):
            if int(x) > 255:
                return False

        # also reject IPs ending with .0 or .255
        if ip.endswith(b'.0') or ip.endswith(b'.255'):
            return False

        # BOGON IP ADDRESS RANGES:
        # source: http://www.team-cymru.org/Services/Bogons/bogon-dd.html

        if bogon is not None:
            # extract 1st and 2nd decimal number from IP as int:
            ip_bytes = ip.split(b'.')
            byte1 = int(ip_bytes[0])
            byte2 = int(ip_bytes[1])
            # print 'ip=%s byte1=%d byte2=%d' % (ip, byte1, byte2)

            # actually we might want to see the following bogon IPs if malware uses them
            # => this should be an option
            # 10.0.0.0 255.0.0.0
            if ip.startswith(b'10.'):
                return False
            # 100.64.0.0 255.192.0.0
            if ip.startswith(b'100.') and (byte2 & 192 == 64):
                return False
            # 127.0.0.0 255.0.0.0
            if ip.startswith(b'127.'):
                return False
            # 169.254.0.0 255.255.0.0
            if ip.startswith(b'169.254.'):
                return False
            # 172.16.0.0 255.240.0.0
            if ip.startswith(b'172.') and (byte2 & 240 == 16):
                return False
            # 192.0.0.0 255.255.255.0
            if ip.startswith(b'192.0.0.'):
                return False
            # 192.0.2.0 255.255.255.0
            if ip.startswith(b'192.0.2.'):
                return False
            # 192.168.0.0 255.255.0.0
            if ip.startswith(b'192.168.'):
                return False
            # 198.18.0.0 255.254.0.0
            if ip.startswith(b'198.') and (byte2 & 254 == 18):
                return False
            # 198.51.100.0 255.255.255.0
            if ip.startswith(b'198.51.100.'):
                return False
            # 203.0.113.0 255.255.255.0
            if ip.startswith(b'203.0.113.'):
                return False
            # 224.0.0.0 240.0.0.0
            if byte1 & 240 == 224:
                return False
            # 240.0.0.0 240.0.0.0
            if byte1 & 240 == 240:
                return False

        # otherwise it's a valid IP adress
        return True

    def email_filter(self, value, **_):
        # check length, e.g. longer than xy@hp.fr
        # check case? e.g. either lower, upper, or capital (but CamelCase covers
        # almost everything... the only rejected case would be starting with lower
        # and containing upper?)
        # or reject mixed case in last part of domain name? (might filter 50% of
        # false positives)
        # optionally, DNS MX query with caching?

        user, domain = value.split(b'@', 1)
        if len(user) < 3:
            return False
        if len(domain) < 5:
            return False
        tld = domain.rsplit(b'.', 1)[1].lower()
        if tld not in self.TDLS:
            return False

        return True

    def domain_filter(self, value, **_):
        # check length
        # check match again tlds set
        if len(value) < 10:
            return False
        # No more than 3 domain names
        if value.count(b'.') > 3:
            return False
        uniq_char = ''.join(set(str(value)))
        if len(uniq_char) < 6:
            return False
        fld = value.split(b'.')
        tld = value.rsplit(b'.', 1)[1].lower()
        # If only two domain levels and either second level < 6 char or tld <= 2 char, or top-level not in list
        if (len(fld) <= 2 and len(fld[0]) < 6) or tld not in self.TDLS:
            return False
        return True

    @staticmethod
    def str_filter(value, **_):
        """
        String filter: avoid false positives with random case. A typical string
        should be either:
        - all UPPERCASE
        - all lowercase
        - or Capitalized
        return True if OK, False otherwise.
        Usage: This filter is meant to be used with string patterns that catch words
        with the option nocase=True, but where random case is not likely.
        Note 1: It is assumed the string only contains alphabetical characters (a-z)
        Note 2: this filter does not cover CamelCase strings.
        """
        # case 1: all UPPERCASE
        # case 2: all lowercase except 1st character which can be uppercase (Capitalized)
        if value.isupper() or value[1:].islower():
            return True
        # Note: we could also use istitle() if strings are not only alphabetical.

    @staticmethod
    def len_filter(value, **_):
        if len(value) < 10:
            return False
        return True

# --- BBCrack Patterns -------------------------------------------------------------------------------------------------

    def bbcr(self, level=1):

        if level == 'small_string':
            bbcrack_patterns = [
                Pattern_re("FTP://_NET_FULL_URI", self.PAT_ANYFTP, weight=100),
                Pattern_re("HTTP://_NET_FULL_URI", self.PAT_ANYHTTP, weight=100),
                Pattern_re("HTTPS://_NET_FULL_URI", self.PAT_ANYHTTPS, weight=100),
            ]
            return bbcrack_patterns

        bbcrack_patterns = [
            Pattern_re("EXE_HEAD", self.PAT_EXEHEADER, weight=100),
            Pattern_re("EXE_DOS", self.PAT_EXEDOS, weight=100),
            Pattern_re("NET_FULL_URI", self.PAT_URL, weight=100),
        ]

        if level == 2:
            # Add PEStudio's API String list, weight will default to 1:
            for k, i in self.PEST_API.items():
                if k == "topapi" or k == "lib":
                    for e in i:
                        if len(e) > 6:
                            bbcrack_patterns.append(Pattern('file.string.api', e, nocase=True, weight=1000))

        return bbcrack_patterns
