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
    else:
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

    def __init__(self, raw_data):
        self.ip_packet = IPPacket(raw_data)
        self.response_timestamps = dict()
        icmp_packet = raw_data.getlayer(2)
        self._id = getattr(icmp_packet, 'id')
        acknowledged = False if getattr(icmp_packet, 'type') == 8 else True
        self.response_timestamps[getattr(icmp_packet, 'seq')] = [acknowledged, float(icmp_packet.time), 0.0, 0.0, 0]

    def update(self, raw_data, swap=False):
        icmp_packet = raw_data.getlayer(1)
        seq_id = getattr(icmp_packet, 'seq')
        if swap:
            self.response_timestamps[seq_id][2] = float(icmp_packet.time)
            self.response_timestamps[seq_id][3] = float(icmp_packet.time) - self.response_timestamps[seq_id][1]
            self.response_timestamps[seq_id][0] = True
        else:
            if seq_id in self.response_timestamps:
                # ICMP request resent
                self.response_timestamps[seq_id][4] += 1
            else:
                # New request
                self.response_timestamps[seq_id] = [False, float(icmp_packet.time), 0.0, 0.0, 0]

    def avg_response_time(self):
        avg_res = 0.0
        for key in self.response_timestamps:
            query = self.response_timestamps[key]
            if query[4] > 0:
                continue
            avg_res += query[3]
        avg_res = avg_res / len(self.response_timestamps)
        return avg_res

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

    def __str__(self):
        return f'{self.ip_packet}, ICMP, No. of req/res:{len(self.response_timestamps)}, Avg:{self.avg_response_time()}, Retries:{self.count_retries()}, Failed:{self.count_failed()}'

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
    protocol = ''
    connection_finished = False
    unintended_connection = False

    def __init__(self, raw_data):
        self.s_port = getattr(raw_data, 'sport')
        self.d_port = getattr(raw_data, 'dport')
        self.ip_packet = IPPacket(raw_data)
        self.protocol = known_protocols[self.d_port] if (self.d_port) in known_protocols else 'UNKNOWN'

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
        if not self.connection_finished:
            if swap:
                # Here the segment is coming from the server
                if not self.server_ack:
                    self.server_ack = getattr(raw_data, 'ack')
                self.data_uploaded += getattr(raw_data, 'ack') - self.server_ack
                self.server_ack = getattr(raw_data, 'ack')
            else:
                if not self.client_ack:
                    self.client_ack = getattr(raw_data, 'ack')
                self.data_downloaded += getattr(raw_data, 'ack') - self.client_ack
                self.client_ack = getattr(raw_data, 'ack')

    def is_unintended(self):
        return 'Unintended' if self.unintended_connection else ''

    def __str__(self):
        return f'{self.ip_packet}, {self.s_port}->{self.d_port}, TCP:{self.protocol}, Download: {self.data_downloaded}, Upload: {self.data_uploaded}, {self.is_unintended()}'

# Store UDP Datagram info
class UDPDatagram:
    s_port = ''
    d_port = ''
    ip_packet = None
    protocol = ''
    downloaded = 0
    uploaded = 0
    app_layer = None

    def __init__(self, raw_data):
        self.ip_packet = IPPacket(raw_data)
        self.s_port = getattr(raw_data, 'sport')
        self.d_port = getattr(raw_data, 'dport')
        self.protocol = known_protocols[self.d_port] if (self.d_port) in known_protocols else 'UNKNOWN'
        if self.d_port == 53:
            self.app_layer = DNS(raw_data)

    def update(self, raw_data, swap=False):
        if self.app_layer:
            self.app_layer.update(raw_data, swap=swap)
        else:
            udp_data = raw_data['UDP']
            if swap:
                self.downloaded += getattr(udp_data, 'len') - 8
            else:
                self.uploaded += getattr(udp_data, 'len') - 8

    def dns_or_download(self):
        if self.app_layer:
            return f'{self.app_layer}'
        else:
            return f'Download: {self.downloaded}, Upload: {self.uploaded}'

    def __str__(self):
        return f'{self.ip_packet} {self.s_port}->{self.d_port}, UDP:{self.protocol} {self.dns_or_download()}'

class DNS:
    record_type = None
    query_response_time = None
    query_initiated = None
    domain_name = ''
    ip_address = None # Only applicable if A/AAAA record in use

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
                if self.record_type in ['A', 'AAAA']:
                    response = getattr(dns_an, 'rdata')
                    if type(response) == bytes:
                        response = response.decode('utf-8')
                    self.ip_address = response 
                    if response.split('.')[-1] == '':
                        self.record_type = 'CNAME'
                if self.query_initiated:
                    self.query_response_time = float(raw_data.time) - self.query_initiated

    def __str__(self):
        return f'{self.domain_name}->{self.ip_address}, {self.record_type} in {self.query_response_time}'