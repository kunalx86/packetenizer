# SCAPY Unofficial documentation for understanding API

* By default rdpcap() returns list of packets that can be iterated.
* List of methods available for packets
__all_slots__
__bool__
__bytes__
__class__
__contains__
__deepcopy__
__delattr__
__delitem__
__dict__
__dir__
__div__
__doc__
__eq__
__format__
__ge__
__getattr__
__getattribute__
__getitem__
__getstate__
__gt__
__hash__
__init__
__init_subclass__
__iter__
__iterlen__
__le__
__len__
__lt__
__module__
__mul__
__ne__
__new__
__nonzero__
__rdiv__
__reduce__
__reduce_ex__
__repr__
__rmul__
__rtruediv__
__setattr__
__setitem__
__setstate__
__sizeof__
__slots__
__str__
__subclasshook__
__truediv__
__weakref__
_answered
_defrag_pos
_do_summary
_name
_overload_fields
_pkt
_resolve_alias
_show_or_dump
_superdir
add_payload
add_underlayer
aliastypes
answers
build
build_done
build_padding
build_ps
canvas_dump
class_default_fields
class_default_fields_ref
class_dont_cache
class_fieldtype
class_packetfields
clear_cache
clone_with
command
convert_packet
convert_packets
convert_to
copy
copy_field_value
copy_fields_dict
decode_payload_as
default_fields
default_payload_class
delfieldval
deprecated_fields
direction
dispatch_hook
display
dissect
dissection_done
do_build
do_build_payload
do_build_ps
do_dissect
do_dissect_payload
do_init_cached_fields
do_init_fields
dst
explicit
extract_padding
fields
fields_desc
fieldtype
firstlayer
fragment
from_hexcap
get_field
getfield_and_val
getfieldval
getlayer
guess_payload_class
hashret
haslayer
hide_defaults
init_fields
iterpayloads
lastlayer
layers
lower_bonds
match_subclass
mysummary
name
original
overload_fields
overloaded_fields
packetfields
payload
payload_guess
pdfdump
post_build
post_dissect
post_dissection
post_transforms
pre_dissect
prepare_cached_fields
psdump
raw_packet_cache
raw_packet_cache_fields
remove_payload
remove_underlayer
route
self_build
sent_time
setfieldval
show
show2
show_indent
show_summary
sniffed_on
sprintf
src
summary
svgdump
time
type
underlayer
update_sent_time
upper_bonds
wirelen
* packet[layer_name] can be done to access that particular layer. E.g. `packet['TCP'] gives you access to TCP Layer of the packet`.
* packet.fields gives a list of fields that can be indexed to a dict. E.g. `{'length': None, 'id': 45501, 'qr': 0, 'opcode': 0, 'aa': 0, 'tc': 0, 'rd': 1, 'ra': 0, 'z': 0, 'ad': 0, 'cd': 0, 'rcode': 0, 'qdcount': 1, 'ancount': 0, 'nscount': 0, 'arcount': 0, 'qd': <DNSQR  qname='registry.npmjs.org.' qtype=A qclass=IN |>, 'an': None, 'ns': None, 'ar': None} for a DNS query`.
* In order to get access to value of a field following can be done. E.g. `getattr(tcp_packet, 'dport') => 443`.
## E.g. Code
```
f = rdpcap("./download.pcap")
for packet in f:
    if packet.getlayer(2).name == 'TCP':
        tcp_packet = packet['TCP']
        if getattr(tcp_packet, 'dport') == 443:
            print(getattr(tcp_packet,'seq'), getattr(tcp_packet, 'ack'))
```
** The above will print sequence number (raw) and acknowledgement number (raw) for tcp segments whose destination port is 443 (HTTPS).

## DNS Stuff 
```
dns_query = packet['DNS']  
DNS Query  
length:None, id:30144, qr:0, opcode:0, aa:0, tc:0, rd:1, ra:0, z:0, ad:0, cd:0, rcode:0, qdcount:1, ancount:0, nscount:0, arcount:0, qd:b'\x03www\x06netbsd\x03org\x00\x00\x01\x00\x01', an:None, ns:None, ar:None  
dns_response = packet['DNS']  
DNS Response
length:None, id:30144, qr:1, opcode:0, aa:0, tc:0, rd:1, ra:1, z:0, ad:0, cd:0, rcode:0, qdcount:1, ancount:1, nscount:0, arcount:0, qd:b'\x03www\x06netbsd\x03org\x00\x00\x01\x00\x01', an:b'\x03www\x06netbsd\x03org\x00\x00\x01\x00\x01\x00\x01@\xef\x00\x04\xcc\x98\xbe\x0c', ns:None, ar:None  
```
