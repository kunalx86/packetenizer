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