#TODO: Implement the important classes

#TODO: Fill this up!
known_protocols = {
    80: 'HTTP',
    443: 'HTTPS',
    22: 'SSH',
}

def extract_socket(raw_packet):
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
    def update(self, swap=True):
        pass

    def __str__(self):
        return ''

class ICMP:
    #TODO: Implement ICMP 
    def __init__(self, raw_data):
        pass

    def update(self, swap=False):
        pass

    def __str__(self):
        return ''

class IPPacket:
    s_ip_addr = ''
    d_ip_addr = ''

    def __init__(self, raw_data):
        self.s_ip_addr = raw_data.getlayer(1).src
        self.d_ip_addr = raw_data.getlayer(1).dst

class TCPSegment:
    s_port = ''
    d_port = ''
    ip_packet = None
    data_downloaded = 0 # Download and upload in the context of client
    data_uploaded = 0
    current_ack = None # From the pov of client
    current_syn = None
    protocol = ''

    def __init__(self, raw_data):
        self.s_port = getattr(raw_data, 'sport')
        self.d_port = getattr(raw_data, 'dport')
        self.ip_packet = IPPacket(raw_data)
        self.current_syn = getattr(raw_data, 'seq')
        self.protocol = known_protocols[self.d_port] if (self.d_port) in known_protocols else 'UNKNOWN'

    def update(self, raw_data, swap=False):
        if swap:
            # Here the segment is coming from the server
            if not self.current_ack:
                self.current_ack = getattr(raw_data, 'seq')
            # Ack from server = Data uploaded (from client POV)
            # Syn from server = Data downloaded (from client POV)
            self.data_downloaded = getattr(raw_data, 'seq') - self.current_ack
            self.current_ack = getattr(raw_data, 'seq')
        else:
            self.data_uploaded += getattr(raw_data, 'seq') - self.current_syn
            self.current_syn = getattr(raw_data, 'seq')

    def __str__(self):
        return f'{self.s_port}->{self.d_port}, {self.protocol}, Download: {self.data_downloaded}, Upload: {self.data_uploaded}'

class UDPDatagram:
    s_port = ''
    d_port = ''
    ip_packet = None

    def __init__(self, raw_data):
        self.s_port = getattr(raw_data, 'sport')
        self.d_port = getattr(raw_data, 'dport')
        self.ip_packet = IPPacket(raw_data)

    def update(self, raw_data, swap=False):
        pass

    def __str__(self):
        return f'{self.s_port}->{self.d_port}'