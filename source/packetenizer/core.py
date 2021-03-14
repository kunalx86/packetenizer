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
            s_socket, d_socket = module.extract_socket(packet)
            if not s_socket or not d_socket:
                continue
            else:
                if not (s_socket, d_socket) in self._core_dict:
                    if not (d_socket, s_socket) in self._core_dict:
                        # The connection doesn't exist create a new one
                        self._core_dict[(s_socket, d_socket)] = module.create_connection(packet)
                    else:
                        # The connection does exist just set the swap=true
                        self._core_dict[(d_socket, s_socket)].update(packet, swap=True)
                        pass

    def __str__(self):
        return self._core_dict.__str__()