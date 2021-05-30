from scapy.error import Scapy_Exception
from scapy.all import rdpcap
from packetenizer.core import CoreStructure
from packetenizer.helper.analyzer import analyze
from io import BufferedReader

def parse_and_analyze(uploaded_file):
    try:
        parsed_file = rdpcap(BufferedReader(uploaded_file))
        core_structure = CoreStructure(parsed_file)
        core_structure.start()
        aggregated_dict = {}
        problem_ips = []
        aggregated_dict, problem_ips = analyze(core_structure)
        serialized_dict = core_structure.serialize(aggregated_dict, problem_ips)
    except Scapy_Exception:
        return "Scapy failed to parse file", False
    except Exception:
        return "Unknown Error", False
    return serialized_dict, True