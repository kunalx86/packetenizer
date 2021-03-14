#TODO: Implement the important classes
class IPPacket:
    s_ip_addr = ''
    d_ip_addr = ''

class TCPSegment:
    s_port = ''
    d_port = ''
    ip_packet = None

class UDPDatagram:
    s_port = ''
    d_port = ''
    ip_packet = None