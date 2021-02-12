from .helper import module

class CoreStructure:
    '''
    This is the root of all class where the core
    dictionary is stored
    '''
    _core_dict = dict()
    _packets = None

    def __init__(self, scapy_packets):
        '''
        __init__(scapy_packets: scapy.plist.PacketList) -> void
        It expects a scapy parsed dump file
        '''
        self._packets = scapy_packets

    def start(self):
        '''
        start() -> void
        This function begins the actual analysis of scapy parsed file
        '''
        for packet in self._packets:
            #!TODO: Implement the core loop
            if not packet.getlayer(2):
                pass
            elif packet.getlayer(2).name == 'TCP':
                pass
            elif packet.getlayer(2).name == 'UDP':
                pass

    def __str__(self):
        return self._core_dict.__str__()