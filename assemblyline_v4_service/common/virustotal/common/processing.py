import json
import time

from collections import defaultdict
from typing import List, Dict, Any

from assemblyline.common import forge
from assemblyline_v4_service.common.result import ResultSection, Heuristic, BODY_FORMAT

Classification = forge.get_classification()


def format_time_from_epoch(t):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(t))


class AVResultsProcessor():

    def __init__(self, term_blocklist: List[str], revised_sig_score_map: Dict[str, int],
                 revised_kw_score_map: Dict[str, int], sig_safelist: List[str] = []):
        self.term_blocklist = term_blocklist
        self.revised_sig_score_map = revised_sig_score_map
        self.revised_kw_score_map = revised_kw_score_map
        [self.revised_kw_score_map.update({sig: 0}) for sig in sig_safelist]

    # Create a results section based on AV reports
    def get_av_results(self, av_report: Dict[str, Any]):
        # Scans
        av_section = ResultSection("AV Detections as Infected or Suspicious")
        no_AV = defaultdict(list)
        for av, details in sorted(av_report.items()):
            result = details['result']
            sig = f"{av}.{result}"
            if result and not any(term in sig for term in self.term_blocklist):
                av_sub = ResultSection(f"{av} identified file as {result}",
                                       body=json.dumps(details),
                                       body_format=BODY_FORMAT.KEY_VALUE,
                                       parent=av_section, classification=Classification.UNRESTRICTED)
                heur = Heuristic(1)
                if sig in self.revised_sig_score_map:
                    heur.add_signature_id(sig, self.revised_sig_score_map[sig])
                elif any(kw in sig.lower() for kw in self.revised_kw_score_map):
                    # Find the kw and apply score
                    heur.add_signature_id(sig, max([self.revised_kw_score_map[kw]
                                                    for kw in self.revised_kw_score_map if kw in sig.lower()]))

                else:
                    heur.add_signature_id(sig)
                av_sub.set_heuristic(heur)
                av_sub.add_tag('av.virus_name', result)
            else:
                category = details.get('category', None)
                if av in self.term_blocklist:
                    no_AV['Blocklisted'].append(av)
                else:
                    no_AV[category].append(av) if category else None

        no_av_section = ResultSection(
            "No Threat Detected by AV Engine(s)", body=json.dumps(no_AV),
            body_format=BODY_FORMAT.KEY_VALUE, classification=Classification.UNRESTRICTED, auto_collapse=True) if no_AV else None

        return av_section, no_av_section
