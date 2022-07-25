# DEFAULT VALUES: usage should defined from service config
# # AV Blocklist (ignore results)
# AV_BLOCKLIST = ["Antiy-AVL", "APEX", "Jiangmin"]


# # Specific signature combos
# REVISED_SIG_SCORE_MAP = {
#     "Ikarus.Trojan-Downloader.MSWord.Agent": 0,
#     "Ikarus.Trojan-Downloader.VBA.Agent": 0,
#     "NANOAV.Exploit.Xml.CVE-2017-0199.equmby": 0,
#     "TACHYON.Suspicious/XOX.Obfus.Gen.2": 100,
#     "TACHYON.Suspicious/XOX.Obfus.Gen.3": 0,
#     "Vir.IT eXplorer.Office.VBA_Macro_Heur": 0,
#     "Vir.IT eXplorer.W97M/Downloader.AB": 0,
# }

# # Specific keywords that could be in signature
# REVISED_KW_SCORE_MAP = {
#     "adware": 100
# }

# # Virus name exception list
# VIRUS_NAME_EXCEPTIONS = ['not-a-virus']

# Capability lookup to att&ck id (v3 only)
CAPABILITY_LOOKUP = {
    "bitcoin": "T1496",
    "create_com_service": "T1569",
    "create_service": "T1569",
    "cred_ff": "T1555",
    "cred_ie7": "T1555",
    "cred_local": "T1003",
    "cred_vnc": "T1552",
    "dyndns": "T1552",
    "escalate_priv": "T1134",
    "hijack_network": "T1090",
    "inject_thread": "T1055",
    "keylogger": "T1056",
    "ldpreload": "T1574",
    "lookupgeo": "T1593",
    "lookupip": "T1593",
    "migrate_apc": "T1055",
    "network_dga": "T1568",
    "network_dns": "T1568",
    "network_dropper": "T1071",
    "network_dyndns": "T1568",
    "network_ftp": "T1071",
    "network_http": "T1071",
    "network_irc": "T1071",
    "network_p2p_win": "T1090",
    "network_smtp_dotnet": "T1071",
    "network_smtp_raw": "T1071",
    "network_smtp_vb": "T1071",
    "network_ssl": "T1573",
    "network_tcp_listen": "T1040",
    "network_tcp_socket": "T1095",
    "network_toredo": "T1562",
    "network_udp_sock": "T1095",
    "rat_rdp": "T1219",
    "rat_vnc": "T1219",
    "rat_webcam": "T1219",
    "screenshot": "T1113",
    "sniff_audio": "T1595",
    "sniff_lan": "T1595",
    "spreading_file": "T1080",
    "spreading_share": "T1135",
    "str_win32_http_api": "T1106",
    "str_win32_internet_api": "T1106",
    "str_win32_wininet_library": "T1106",
    "str_win32_winsock2_library": "T1106",
    "win_files_operation": "T1098",
    "win_mutex": "T1106",
    "win_private_profile": "T1098",
    "win_registry": "T1112",
    "win_token": "T1134"
}
