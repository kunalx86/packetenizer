import sys
from scapy.all import rdpcap
from core_module import core

def main():
    if len(sys.argv) <= 1:
        print('Please provide the path to dump file')
        print('Usage: python run.py path/to/dump_file')
        exit(1)
    try:
        scapy_packets = rdpcap(sys.argv[1])
        core_structure = core.CoreStructure(scapy_packets)
        core_structure.start()
        print(core_structure)
    except IOError:
        print('Error!')
        exit(1)

if __name__ == '__main__':
    main()