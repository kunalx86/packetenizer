import sys
from scapy.all import rdpcap 
from packetenizer import core
from packetenizer.helper import module

def main():
    if len(sys.argv) <= 1:
        print('Please provide the path to dump file')
        print('Usage: python run.py path/to/dump_file')
        exit(1)
    try:
        scapy_packets = rdpcap(sys.argv[1]) # Ignore the error
        core_structure = core.CoreStructure(scapy_packets)
        core_structure.start()
        for key in core_structure._core_dict.keys():
            print(core_structure._core_dict[key])
        aggregated_dict = module.analyzer(core_structure)
        for key in aggregated_dict:
            print(aggregated_dict[key])
    except IOError:
        print('Error!')
        exit(1)

if __name__ == '__main__':
    main()