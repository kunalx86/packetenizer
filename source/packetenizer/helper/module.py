import datetime
from itertools import zip_longest

known_protocols = {
    80: 'HTTP',
    443: 'HTTPS',
    22: 'SSH',
    53: 'DNS',
    68: 'DHCP',
    3478: 'STUN',
}

# Binary representation of flags used to mask bits
tcp_flags = {
    'FIN': 0x01,
    'SYN': 0x02,
    'RST': 0x04,
    'PSH': 0x08,
    'ACK': 0x10,
    'URG': 0x20,
    'ECE': 0x40,
    'CWR': 0x80,
}

# Needed for scapy
dns_types = {
    15: 'MX',
    16: 'TXT',
    29: 'LOC',
    12: 'PTR',
    1: 'A',
    28: 'AAAA',
    255: 'ALL',
    2: 'NS',
    33: 'SRV'
}

def debug_packet(raw_packet):
    '''
    Print imp debug info from a packet
    '''
    return f'{raw_packet.name}, {raw_packet.src}->{raw_packet.dst}, {raw_packet.layers}'

def extract_socket(raw_packet):
    '''
    Retrieve socket addresses
    '''
    #TODO: Implement logic to extract identifier for proto other than TCP/UDP
    if raw_packet.getlayer(2) and raw_packet.getlayer(2).name != 'Padding':
        s_ip = raw_packet.getlayer(1).src
        d_ip = raw_packet.getlayer(1).dst
        if raw_packet.getlayer(2).name == 'TCP' or raw_packet.getlayer(2).name == 'UDP':
            s_port = getattr(raw_packet.getlayer(2), 'sport')
            d_port = getattr(raw_packet.getlayer(2), 'dport')
            return (f'{s_ip}:{s_port}', f'{d_ip}:{d_port}')
        elif raw_packet.getlayer(2).name == 'ICMP':
            _id = getattr(raw_packet.getlayer(2), 'id')
            return (f'{s_ip};{_id}', f'{d_ip};{_id}')
    elif raw_packet.getlayer(0):
        s_adr = getattr(raw_packet.getlayer(0), 'src')
        d_adr = getattr(raw_packet.getlayer(0), 'dst')
        return (s_adr, d_adr)
    return (None, None)

def create_connection(raw_packet):
    '''
    Returns the appropriate instance of class that needs to be used
    Better to not clutter up the main loop
    '''
    if raw_packet.getlayer(1):
        # For now we are assuming IP cannot be on it's own
        if raw_packet.getlayer(2):
            if raw_packet.getlayer(2).name == 'ICMP':
                return ICMP(raw_packet)
            elif raw_packet.getlayer(2).name == 'TCP':
                return TCPSegment(raw_packet)
            elif raw_packet.getlayer(2).name == 'UDP':
                return UDPDatagram(raw_packet)
            else:
                return Invalid(raw_packet)
        else:
            return Invalid(raw_packet)
    else:
        # Packet with no IP layer? Ughh will think about this later!
        return Invalid(raw_packet)

class Invalid:
    '''
    Anything that we don't know what to do with goes to this
    '''
    raw_bytes = None
    l2_proto = None
    l3_proto = None

    def __init__(self, raw_data):
        self.raw_bytes = str(raw_data)
        self.l2_proto = raw_data.getlayer(0).name if raw_data.getlayer(0) else 'UNKNOWN'
        self.l3_proto = raw_data.getlayer(1).name if raw_data.getlayer(1) else 'UNKWOWN'

    def update(self, raw_data, swap=True):
        return

    def __str__(self):
        return f'UNKWOWN/INVALID: {self.l2_proto}, {self.l3_proto}'

# For ICMP stuff, but more research needed
class ICMP:
    #TODO: Implement ICMP 
    ip_packet = None
    _id = None
    response_timestamps = dict() # [Reply received?, Request Sent timestamp, Response Received timestamp, Difference, No. of retries]
    _type = None

    def __init__(self, raw_data):
        self.ip_packet = IPPacket(raw_data)
        self.response_timestamps = dict()
        icmp_packet = raw_data.getlayer(2)
        self._id = getattr(icmp_packet, 'id')
        self._type = 'PING' if getattr(icmp_packet, 'type') == 8 else 'PORT UNREACHABLE'
        acknowledged = False if getattr(icmp_packet, 'type') == 8 else True
        self.response_timestamps[getattr(icmp_packet, 'seq')] = [acknowledged, float(raw_data.time), 0.0, 0.0, 0]

    def update(self, raw_data, swap=False):
        icmp_packet = raw_data.getlayer(1)
        seq_id = getattr(icmp_packet, 'seq')
        if swap:
            self.response_timestamps[seq_id][2] = float(raw_data.time)
            self.response_timestamps[seq_id][3] = float(raw_data.time) - self.response_timestamps[seq_id][1]
            self.response_timestamps[seq_id][0] = True
        else:
            if seq_id in self.response_timestamps:
                # ICMP request resent
                self.response_timestamps[seq_id][4] += 1
            else:
                # New request
                self.response_timestamps[seq_id] = [False, float(raw_data.time), 0.0, 0.0, 0]

    def avg_response_time(self):
        avg_res = 0.0
        for key in self.response_timestamps:
            query = self.response_timestamps[key]
            if query[4] > 0:
                continue
            avg_res += query[3]
        avg_res = avg_res / len(self.response_timestamps)
        return datetime.datetime.fromtimestamp(avg_res).microsecond/1000

    def count_retries(self):
        retries = 0
        for key in self.response_timestamps:
            query = self.response_timestamps[key]
            retries += query[4]
        return retries

    def count_failed(self):
        failed = 0
        for key in self.response_timestamps:
            query = self.response_timestamps[key]
            if not query[0]:
                failed += 1
        return failed

    def count_packets(self):
        return len(self.response_timestamps)

    def __str__(self):
        return f'{self.ip_packet}, ICMP {self._type}, No. of req/res:{len(self.response_timestamps)}, Avg:{self.avg_response_time()}ms, Retries:{self.count_retries()}, Failed:{self.count_failed()}'

# To represent IP info
class IPPacket:
    s_ip_addr = ''
    d_ip_addr = ''
    protocol = ''

    def __init__(self, raw_data):
        self.s_ip_addr = raw_data.getlayer(1).src
        self.d_ip_addr = raw_data.getlayer(1).dst
        if len(self.s_ip_addr.split('.')) == 4:
            self.protocol = 'IPv4'
        else:
            self.protocol = 'IPv6'

    def __str__(self):
        return f'{self.s_ip_addr}->{self.d_ip_addr}, {self.protocol}'

# Store TCP segment info
class TCPSegment:
    s_port = ''
    d_port = ''
    ip_packet = None
    data_downloaded = 0 # Download and upload in the context of client
    data_uploaded = 0
    client_ack = None # From the pov of client
    server_ack = None
    app_layer = None
    protocol = ''
    connection_finished = False
    reception_timestamps = []
    transmission_timestamps = []
    unintended_connection = False

    def __init__(self, raw_data):
        self.reception_timestamps = []
        self.transmission_timestamps = []
        self.s_port = getattr(raw_data, 'sport')
        self.d_port = getattr(raw_data, 'dport')
        self.ip_packet = IPPacket(raw_data)
        self.protocol = known_protocols[self.d_port] if (self.d_port) in known_protocols else 'UNKNOWN'
        self.app_layer = DNS(raw_data) if self.d_port == 53 else None
        self.transmission_timestamps.append(float(raw_data.time))

    def update(self, raw_data, swap=False):
        # This implementation should be good enough for now
        # Download/upload seems to be updating as intended
        # We are also counting the magic byte, but it shouldn't affect anything drastically

        # Ack from server = Data uploaded (from client POV)
        # Ack from client = Data downloaded (from client POV)
        flags = raw_data['TCP'].flags # Correct way to get flags
        if flags & tcp_flags['FIN'] or flags & tcp_flags['RST']:
            # If the connection is Resetted or Finished we will no longer update the download/upload
            self.connection_finished = True 
            if not self.server_ack:
                self.unintended_connection = True
            return

        if self.app_layer:
            self.app_layer.update(raw_data, swap)
        else:
            if not self.connection_finished:
                if swap:
                    # Here the segment is coming from the server
                    self.transmission_timestamps.append(float(raw_data.time))
                    if not self.server_ack:
                        self.server_ack = getattr(raw_data, 'ack')
                    self.data_uploaded += getattr(raw_data, 'ack') - self.server_ack
                    self.server_ack = getattr(raw_data, 'ack')
                else:
                    self.reception_timestamps.append(float(raw_data.time))
                    if not self.client_ack:
                        self.client_ack = getattr(raw_data, 'ack')
                    self.data_downloaded += getattr(raw_data, 'ack') - self.client_ack
                    self.client_ack = getattr(raw_data, 'ack')

    def get_average_timestamps(self):
        r_avg, t_avg = (0.0, 0.0)
        for r_time, t_time in zip_longest(self.reception_timestamps, self.transmission_timestamps):
            r_avg += r_time if r_time else 0
            t_avg += t_time if t_time else 0
        r_avg = r_avg / len(self.reception_timestamps) if len(self.reception_timestamps) != 0 else -1
        t_avg = t_avg / len(self.transmission_timestamps) if len(self.transmission_timestamps) != 0 else -1
        r_avg = datetime.datetime.fromtimestamp(r_avg).microsecond/1000
        t_avg = datetime.datetime.fromtimestamp(t_avg).microsecond/1000
        return (r_avg, t_avg)

    def is_unintended(self):
        return 'Unintended' if self.unintended_connection else ''
    
    def get_download(self):
        return self.data_downloaded

    def get_upload(self):
        return self.data_uploaded
    
    def print_dns(self):
        return self.app_layer if self.app_layer else ''

    def is_dns(self):
        return True if self.app_layer else False

    def __str__(self):
        r_avg, t_avg = self.get_average_timestamps()
        return f'{self.ip_packet}, {self.s_port}->{self.d_port}, TCP:{self.protocol}, {self.print_dns()} Download: {self.data_downloaded}, Upload: {self.data_uploaded}, {self.is_unintended()} Avg Rec/Tra gap: {r_avg}/{t_avg}ms'

# Store UDP Datagram info
class UDPDatagram:
    s_port = ''
    d_port = ''
    ip_packet = None
    protocol = ''
    downloaded = 0
    uploaded = 0
    reception_timestamps = []
    transmission_timestamps = []
    app_layer = None

    def __init__(self, raw_data):
        self.ip_packet = IPPacket(raw_data)
        self.s_port = getattr(raw_data, 'sport')
        self.d_port = getattr(raw_data, 'dport')
        self.downloaded, self.uploaded = (0, 0)
        self.reception_timestamps = []
        self.transmission_timestamps = []
        self.protocol = known_protocols[self.d_port] if (self.d_port) in known_protocols else 'UNKNOWN'
        if self.d_port == 53:
            self.app_layer = DNS(raw_data)
        else:
            self.transmission_timestamps.append(float(raw_data.time))


    def update(self, raw_data, swap=False):
        if self.app_layer:
            self.app_layer.update(raw_data, swap=swap)
        else:
            udp_data = raw_data['UDP']
            if swap:
                self.reception_timestamps.append(float(raw_data.time))
                self.downloaded += getattr(udp_data, 'len') - 8
            else:
                self.transmission_timestamps.append(float(raw_data.time))
                self.uploaded += getattr(udp_data, 'len') - 8
    
    def get_download(self):
        return self.downloaded

    def get_upload(self):
        return self.uploaded

    def get_average_timestamps(self):
        r_avg, t_avg = (0.0, 0.0)
        for r_time, t_time in zip_longest(self.reception_timestamps, self.transmission_timestamps):
            r_avg += r_time if r_time else 0
            t_avg += t_time if t_time else 0
        r_avg = r_avg / len(self.reception_timestamps) if len(self.reception_timestamps) != 0 else -1
        t_avg = t_avg / len(self.transmission_timestamps) if len(self.transmission_timestamps) != 0 else -1
        r_avg = datetime.datetime.fromtimestamp(r_avg).microsecond/1000
        t_avg = datetime.datetime.fromtimestamp(t_avg).microsecond/1000
        return (r_avg, t_avg)

    def is_dns(self):
        return True if self.app_layer else False

    def dns_or_download(self):
        if self.app_layer:
            return f'{self.app_layer}'
        else:
            return f'Download: {self.downloaded}, Upload: {self.uploaded}'

    def __str__(self):
        r_avg, t_avg = self.get_average_timestamps()
        return f'{self.ip_packet} {self.s_port}->{self.d_port}, UDP:{self.protocol} {self.dns_or_download()}, Avg Rec/Tra Gap: {r_avg}/{t_avg}'

class DNS:
    record_type = None
    query_response_time = None
    query_initiated = None
    domain_name = ''
    ip_address = None # It is not necessary for this to be IP, consider it to be a response

    def __init__(self, raw_data):
        dns_data = raw_data['DNS']
        dns_qd = getattr(dns_data, 'qd')
        self.record_type = dns_types[getattr(dns_qd, 'qtype')] if dns_types[getattr(dns_qd, 'qtype')] else 'UNKNOWN'
        if getattr(dns_data, 'ra') == 0:
            # The initial DNS can or cannot be a query
            # If it is a query we do set query_initiated
            self.query_initiated = float(raw_data.time)
        self.domain_name = getattr(dns_qd, 'qname').decode('utf-8')

    def update(self, raw_data, swap=False):
        dns_data = raw_data['DNS']
        if swap:
            dns_an = getattr(dns_data, 'an')
            if dns_an:
                if self.record_type in ['A', 'AAAA', 'MX', 'NS', 'SRV', 'PTR']:
                    response = getattr(dns_an, 'rdata')
                    if type(response) == bytes:
                        response = response.decode('utf-8')
                    self.ip_address = response 
                    if response.split('.')[-1] == '' and self.record_type in ['A', 'AAAA']:
                        self.record_type = 'CNAME'
                if self.query_initiated:
                    dt = float(raw_data.time)
                    self.query_response_time = dt - self.query_initiated
                    dt = datetime.datetime.fromtimestamp(self.query_response_time)
                    self.query_response_time = dt.microsecond/1000

    def __str__(self):
        return f'{self.domain_name}->{self.ip_address}, {self.record_type} in {self.query_response_time}ms'
        
def get_addr_from_socket(socket):
    if len(socket.split(':')) > 1 and len(socket.split(':')) < 5:
        return socket.split(':')[0]
    else:
        return socket.split(';')[0]

def init_tcp_agg_dict():
    return {
        'type': 'TCP',
        's/d': (None, None),
        'uploaded': 0,
        'downloaded': 0,
        'unintended': 0,
        'avg_rec': 0.0,  # Might get rid of this and below
        'avg_trans': 0.0,
        'connections': 0,
    }

def init_udp_agg_dict():
    return {
        'type': 'UDP',
        's/d': (None, None),
        'uploaded': 0,
        'downloaded': 0,
        'avg_rec': 0.0,
        'avg_trans': 0.0,
        'connections': 0,
    }

def init_dns_agg_dict():
    return {
        'type': 'DNS',
        'avg_response_time': 0.0,
        'queries_resolved': 0,
        'total_queries': 0,
    }

def init_icmp_agg_dict():
    return {
        'type': 'ICMP',
        's/d': (None, None),
        'total_packets': 0,
        'avg_ping': 0.0,
        'connections': 0,
    }

def init_invalid_agg_dict():
    return {
        'type': 'INVALID'
    }

def analyzer(core_structure):
    aggregated_dict = {}
    core_dict = core_structure._core_dict
    for key in core_dict:
        current_core_obj = core_dict[key]
        s_socket, d_socket = key
        d_addr = get_addr_from_socket(d_socket)
        s_addr = get_addr_from_socket(s_socket)
        is_dns = False
        if isinstance(current_core_obj, UDPDatagram) or isinstance(current_core_obj, TCPSegment):
            is_dns = current_core_obj.is_dns()
        # (1.1.1.1, 8.8.8.8) => (1.1.1.1;t/u/d/i/n, 8.8.8.8;t/u/d/i/n)
        _key = ''
        if (isinstance(current_core_obj, TCPSegment) or isinstance(current_core_obj, UDPDatagram)) and not is_dns:
            if isinstance(current_core_obj, TCPSegment):
                _key = (f'{s_addr};t', f'{d_addr};t')
                current_agg_obj = aggregated_dict[_key] if _key in aggregated_dict else init_tcp_agg_dict()
                current_agg_obj['s/d'] = (s_addr, d_addr)
            else:
                _key = (f'{s_addr};u', f'{d_addr};u')
                current_agg_obj = aggregated_dict[_key] if _key in aggregated_dict else init_udp_agg_dict()
                current_agg_obj['s/d'] = (s_addr, d_addr)
            current_agg_obj['uploaded'] += current_core_obj.get_upload()
            current_agg_obj['downloaded'] += current_core_obj.get_download()
            if isinstance(current_core_obj, TCPSegment):
                current_agg_obj['unintended'] += 1 if current_core_obj.is_unintended() != '' else 0
            avg_rec, avg_trans = current_core_obj.get_average_timestamps()
            current_agg_obj['avg_rec'] += avg_rec
            current_agg_obj['avg_trans'] += avg_trans
            current_agg_obj['connections'] += 1
        elif is_dns:
            # For DNS we will aggregate only on the basis of DNS server
            _key = (f'{d_addr};d')
            current_agg_obj = aggregated_dict[_key] if _key in aggregated_dict else init_dns_agg_dict()
            current_agg_obj['total_queries'] += 1
            current_core_obj = current_core_obj.app_layer
            if current_core_obj.ip_address:
                current_agg_obj['queries_resolved'] += 1
                current_agg_obj['avg_response_time'] += current_core_obj.query_response_time
        elif isinstance(current_core_obj, ICMP):
            _key = (f'{s_addr};i', f'{d_addr};i')
            current_agg_obj = aggregated_dict[_key] if _key in aggregated_dict else init_icmp_agg_dict()
            current_agg_obj['s/d'] = (s_addr, d_addr)
            current_agg_obj['total_packets'] += len(current_core_obj.response_timestamps)
            current_agg_obj['avg_ping'] += current_core_obj.avg_response_time()
            current_agg_obj['connections'] += 1
        else:
            _key = (f'{s_addr};n', f'{d_addr};n')
            current_agg_obj = aggregated_dict[_key] if _key in aggregated_dict else init_invalid_agg_dict()
            current_agg_obj['s/d'] = (s_addr, d_addr)
        aggregated_dict[_key] = current_agg_obj
    
    # Aggregated Dictionary has been built now
    # Final step is to decide NMAP attack?, DoS Attack?, calculate averages

    TCP_DOS_UPLOADS = 1000
    TCP_UNINTENDED_CONNECTIONS = 0.7

    for key in aggregated_dict:
        current_agg_obj = aggregated_dict[key]
        
        if current_agg_obj['type'] == 'TCP':
            # Calculating the averages
            current_agg_obj['avg_rec'] = current_agg_obj['avg_rec'] / current_agg_obj['connections']
            current_agg_obj['avg_trans'] = current_agg_obj['avg_trans'] / current_agg_obj['connections']

            # Upload is more spread out 
            if current_agg_obj['uploaded'] / current_agg_obj['connections'] / TCP_DOS_UPLOADS > 0.8:
                # DoS
                current_agg_obj['is_dos'] = True
                
            # Connection based comparison
            if current_agg_obj['connections'] > 10000 and (current_agg_obj['downloaded'] < 1000 and current_agg_obj['uploaded'] < 1000):
                # DoS
                current_agg_obj['is_dos'] = True

            if current_agg_obj['unintended'] / current_agg_obj['connections'] > TCP_UNINTENDED_CONNECTIONS:
                # NMAP
                current_agg_obj['is_nmap'] = True

        elif current_agg_obj['type'] == 'UDP':
            # Calculating averages
            current_agg_obj['avg_rec'] = current_agg_obj['avg_rec'] / current_agg_obj['connections']
            current_agg_obj['avg_trans'] = current_agg_obj['avg_trans'] / current_agg_obj['connections']

            if current_agg_obj['uploaded'] > 10000 and current_agg_obj['avg_rec'] == 0.0:
                # Maybe UDP based DoS
                current_agg_obj['is_dos'] = True
        
        elif current_agg_obj['type'] == 'DNS':
            current_agg_obj['avg_response_time'] = current_agg_obj['avg_response_time'] / current_agg_obj['queries_resolved']

        elif current_agg_obj['type'] == 'ICMP':
            # Calculating average
            current_agg_obj['avg_ping'] = current_agg_obj['avg_ping'] / current_agg_obj['connections']

            # Maybe ICMP based attack or just sus 😳❗ behaviour
            if current_agg_obj['total_packets'] > 20:
                # Sus behaviour
                current_agg_obj['sus'] = True
        else:
            continue 

    return aggregated_dict