from .helper import module
from scapy.plist import PacketList
class CoreStructure:
    '''
    This is the root of all class where the core
    dictionary is stored
    '''
    _core_dict = dict()
    _packets = None

    def __init__(self, scapy_packets: PacketList):
        '''
        It expects a scapy parsed dump file
        '''
        self._packets = scapy_packets

    def start(self):
        '''
        This function begins the actual analysis of scapy parsed file
        '''
        for packet in self._packets:
            s_socket, d_socket = (None, None)
            try:
                s_socket, d_socket = module.extract_socket(packet)
            except:
                print(f'Error:{packet}')
            if not s_socket or not d_socket:
                continue
                # print('Ughh.. Problem')
                # print(module.debug_packet(packet))
            else:
                try:
                    if not (s_socket, d_socket) in self._core_dict:
                        if not (d_socket, s_socket) in self._core_dict:
                            # The connection doesn't exist create a new one
                            self._core_dict[(s_socket, d_socket)] = module.create_connection(packet)
                        else:
                            # The connection does exist just set the swap=true
                            self._core_dict[(d_socket, s_socket)].update(packet, swap=True)
                    else:
                        self._core_dict[(s_socket, d_socket)].update(packet)
                except:
                    continue
    
    def serialize(self, analyze: dict, problem_ips: list):
        serialized_dict = {
            'tcp': [],
            'udp': [],
            'icmp': [],
            'dns': [],
            'invalid': [],
            'analyze': {
                'tcp': [],
                'udp': [],
                'dns': [],
                'icmp': [],
                'invalid': [],
            },
        }

        for connection in self._core_dict.values():
            connection_serialized_dict = connection.serialize()
            if 'ip' in connection_serialized_dict:
                connection_serialized_dict['invisible'] = compare_ips(problem_ips, connection_serialized_dict['ip'])

            if 'type' in connection_serialized_dict:
                connection_serialized_dict.pop('type', None)
                serialized_dict['dns'].append(connection_serialized_dict)
            elif isinstance(connection, module.TCPSegment):
                serialized_dict['tcp'].append(connection_serialized_dict)
            elif isinstance(connection, module.ICMP):
                serialized_dict['icmp'].append(connection_serialized_dict)
            elif isinstance(connection, module.Invalid):
                serialized_dict['invalid'].append(connection_serialized_dict)
            elif isinstance(connection, module.UDPDatagram):
                serialized_dict['udp'].append(connection_serialized_dict)

        for agg_con in analyze.values():
            if agg_con['type'] != 'DNS':
                s_addr, d_addr = agg_con['s/d']
                agg_con.pop('s/d', None)
                agg_con['source_address'] = s_addr
                agg_con['destination_address'] = d_addr
            serialized_dict['analyze'][agg_con['type'].lower()].append(agg_con)

        return serialized_dict

    def __str__(self):
        return self._core_dict.__str__()

def compare_ips(problem_ips, current_ip):
    s_c_ip = current_ip['source_address']
    d_c_ip = current_ip['destination_address']
    for s_p_ip, d_p_ip in problem_ips:
       if s_c_ip == s_p_ip and d_c_ip == d_p_ip:
           return True
    return False