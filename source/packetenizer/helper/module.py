#TODO: Implement the important classes

#TODO: Fill this up!
known_protocols = {
    80: 'HTTP',
    443: 'HTTPS',
    22: 'SSH',
    53: 'DNS',
    68: 'DHCP',
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
    if raw_packet.getlayer(2):
        if raw_packet.getlayer(2).name == 'TCP' or raw_packet.getlayer(2).name == 'UDP':
            s_ip = raw_packet.getlayer(1).src
            s_port = getattr(raw_packet.getlayer(2), 'sport')
            d_ip = raw_packet.getlayer(1).dst
            d_port = getattr(raw_packet.getlayer(2), 'dport')
            return (f'{s_ip}:{s_port}', f'{d_ip}:{d_port}')
    return (None, None)

def create_connection(raw_packet):
    '''
    Returns the appropriate instance of class that needs to be used
    Better to not clutter up the main loop
    '''
    if raw_packet.getlayer(1):
        # For now we are assuming IP cannot be on it's own
        if raw_packet.getlayer(2).name == 'ICMP':
            return ICMP(raw_packet)
        elif raw_packet.getlayer(2).name == 'TCP':
            return TCPSegment(raw_packet)
        elif raw_packet.getlayer(2).name == 'UDP':
            return UDPDatagram(raw_packet)
    else:
        # Packet with no IP layer? Ughh will think about this later!
        return Invalid()

class Invalid:
    '''
    Anything that we don't know what to do with goes to this
    '''

    def update(self, swap=True):
        pass

    def __str__(self):
        return ''

# For ICMP stuff, but more research needed
class ICMP:
    #TODO: Implement ICMP 
    def __init__(self, raw_data):
        pass

    def update(self, swap=False):
        pass

    def __str__(self):
        return ''

# To represent IP info
class IPPacket:
    s_ip_addr = ''
    d_ip_addr = ''

    def __init__(self, raw_data):
        self.s_ip_addr = raw_data.getlayer(1).src
        self.d_ip_addr = raw_data.getlayer(1).dst

    def __str__(self):
        return f'{self.s_ip_addr}->{self.d_ip_addr}'

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

    def __str__(self):
        return f'{self.ip_packet}, {self.s_port}->{self.d_port}, {self.protocol}, Download: {self.data_downloaded}, Upload: {self.data_uploaded}'

# Store UDP Datagram info
class UDPDatagram:
    s_port = ''
    d_port = ''
    ip_packet = None
    protocol = ''

    def __init__(self, raw_data):
        self.s_port = getattr(raw_data, 'sport')
        self.d_port = getattr(raw_data, 'dport')
        self.ip_packet = IPPacket(raw_data)
        self.protocol = known_protocols[self.d_port] if (self.d_port) in known_protocols else 'UNKNOWN'

    def update(self, raw_data, swap=False):
        pass

    def __str__(self):
        return f'{self.ip_packet} {self.s_port}->{self.d_port}, {self.protocol}'