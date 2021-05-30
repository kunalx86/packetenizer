import sys
from scapy.all import rdpcap
from scapy.error import Scapy_Exception
from packetenizer import core
from packetenizer.helper import module
from packetenizer.helper import analyzer
import json

def main():
    if len(sys.argv) <= 1:
        print('Please provide the path to dump file')
        print('Usage: python run.py path/to/dump_file')
        exit(1)
    try:
        scapy_packets = rdpcap(sys.argv[1]) # Ignore the error
        core_structure = core.CoreStructure(scapy_packets)
        core_structure.start()
        # for key in core_structure._core_dict.keys():
            # print(core_structure._core_dict[key])
        aggregated_dict, problem_ips = analyzer.analyze(core_structure)
        # for key in aggregated_dict:
            # print(aggregated_dict[key])
        serialized_dict = core_structure.serialize(aggregated_dict, problem_ips)
        print(json.dumps(serialized_dict, indent=4))
    except Scapy_Exception:
        print('Couldn\'t parse file')
    except FileNotFoundError:
        print('File doesn\'t exist')
        exit(1)

if __name__ == '__main__':
    main()