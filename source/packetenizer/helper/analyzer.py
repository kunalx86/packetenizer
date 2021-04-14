from .module import ICMP, DNS, TCPSegment, UDPDatagram, Invalid
from packetenizer.core import CoreStructure

def get_addr_from_socket(socket) -> str:
    if len(socket.split(':')) > 1 and len(socket.split(':')) < 5:
        return socket.split(':')[0]
    else:
        return socket.split(';')[0]

def init_tcp_agg_dict() -> dict:
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

def init_udp_agg_dict() -> dict:
    return {
        'type': 'UDP',
        's/d': (None, None),
        'uploaded': 0,
        'downloaded': 0,
        'avg_rec': 0.0,
        'avg_trans': 0.0,
        'connections': 0,
    }

def init_dns_agg_dict() -> dict:
    return {
        'type': 'DNS',
        'avg_response_time': 0.0,
        'queries_resolved': 0,
        'total_queries': 0,
    }

def init_icmp_agg_dict() -> dict:
    return {
        'type': 'ICMP',
        's/d': (None, None),
        'total_packets': 0,
        'avg_ping': 0.0,
        'connections': 0,
    }

def init_invalid_agg_dict() -> dict:
    return {
        'type': 'INVALID',
        'count': 0,
    }

def analyze(core_structure: CoreStructure):
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
            current_agg_obj['server'] = d_addr
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
            current_agg_obj['count'] += 1
        aggregated_dict[_key] = current_agg_obj
    
    # Aggregated Dictionary has been built now
    # Final step is to decide NMAP attack?, DoS Attack?, calculate averages

    TCP_DOS_UPLOADS = 1000
    TCP_UNINTENDED_CONNECTIONS = 0.7
    problem_ips = []

    for key in aggregated_dict:
        current_agg_obj = aggregated_dict[key]
        
        if current_agg_obj['type'] == 'TCP':
            # Calculating the averages
            current_agg_obj['avg_rec'] = current_agg_obj['avg_rec'] / current_agg_obj['connections']
            current_agg_obj['avg_trans'] = current_agg_obj['avg_trans'] / current_agg_obj['connections']

            upload_connections_ratio = current_agg_obj['uploaded'] / current_agg_obj['connections'] / TCP_DOS_UPLOADS
            # Upload is more spread out 
            if upload_connections_ratio > 0.8 and current_agg_obj['connections'] > 10:
                # DoS
                problem_ips.append(current_agg_obj['s/d'])
                current_agg_obj['is_dos'] = True
                
            # Connection based comparison
            if current_agg_obj['connections'] > 10000 and (current_agg_obj['downloaded'] < 1000 and current_agg_obj['uploaded'] < 1000):
                # DoS
                problem_ips.append(current_agg_obj['s/d'])
                current_agg_obj['is_dos'] = True

            if current_agg_obj['unintended'] / current_agg_obj['connections'] > TCP_UNINTENDED_CONNECTIONS and current_agg_obj['connections'] > 10:
                # NMAP
                problem_ips.append(current_agg_obj['s/d'])
                current_agg_obj['is_nmap'] = True

        elif current_agg_obj['type'] == 'UDP':
            # Calculating averages
            current_agg_obj['avg_rec'] = current_agg_obj['avg_rec'] / current_agg_obj['connections']
            current_agg_obj['avg_trans'] = current_agg_obj['avg_trans'] / current_agg_obj['connections']

            if current_agg_obj['uploaded'] > 10000 and current_agg_obj['avg_rec'] == 0.0:
                # Maybe UDP based DoS
                problem_ips.append(current_agg_obj['s/d'])
                current_agg_obj['is_dos'] = True
        
        elif current_agg_obj['type'] == 'DNS':
            try:
               current_agg_obj['avg_response_time'] = current_agg_obj['avg_response_time'] / current_agg_obj['queries_resolved']
            except ZeroDivisionError:
                current_agg_obj['avg_response_time'] = 0.0

        elif current_agg_obj['type'] == 'ICMP':
            # Calculating average
            current_agg_obj['avg_ping'] = current_agg_obj['avg_ping'] / current_agg_obj['connections']

            # Maybe ICMP based attack or just sus 😳❗ behaviour
            if current_agg_obj['total_packets'] > 20:
                # Sus behaviour
                current_agg_obj['sus'] = True
        else:
            continue 

    return aggregated_dict, problem_ips