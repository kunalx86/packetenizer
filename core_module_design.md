# We need a way to store connection information
* We have to make decision at each layer
* E.g. `Ethernet -> IP -> TCP`
* For a typical TCP connection we assume the three way handshake. SYN, SYN-ACK, ACK
* For data transfer. It is typically SYN or SYN-ACK, the data field length can be added
* Keeping this in mind we need a data structure where we can store this information and lookup a table like structure that tells us which connection we should be looking at
* Fields such as data uploaded, downloaded should be done from the perspective of the client. (MAYBE)
* Assuming that we count another connection to same source and destination as different, we can uniquely identify a connection (source socket addr, dest socket addr) -> connection info
* E.g. `(192.168.0.150:54124, 212.451.89.62:443) -> {data_up: 1200, data_down: 10000, ...}`
* Data structure:\
`
{
    (souce socket addr, destination socket addr): {
        data_up: integer,
        data_down: integer,
        secured: boolean,
        l2_proto: string,
        l3_proto: string,
        l4_proto: string,
        l5_proto: string,
        ...
    }
}
`
* The above shall work for traditional TCP, UDP messages. However, lower layer protocols like ICMP, ARP and others need a better solution.
* For ICMP a non used port like 0 can be used. "Some" implementations do use port apparently (I highly doubt the latter one)
* Lower layer messages (E.g. ARP if not needed "can" be skipped entirely)
* Protocols like PPP for example use an identifier which can be used as a key for our dictionary. Ref: [https://tools.ietf.org/html/rfc1334]
* It is also important to note that our "connection variables" shall change depending on the protocol we are dealing with
* UDP connections like DHCP, DNS instead of data_up/down we can have protocol specific fields like dhcp/dns server, query name, cnames, a/aaaa records etc
* Include timestamps wherever possible

## Classes for higher level protocols
* Develop classes for higher level protocols for now UDP, TCP
* Instead of raw key/values for the core dictionary value, create a reference to UDP/TCP object
* Which object to be developed either UDP/TCP can be decided in the main loop based on conditional logic
* Scapy packet value can be passed on to the constructor to set values for the object
* Methods can be provided to update data transferred for example which can be called in the main loop
* Optionally we may also create classes for layer 5 protocols (DHCP, DNS) and if necessary even for TCP based protocols
`
core_structure[key]: UDP(),
core_structure[key]: TCP(),

UDP():
	source
	destination
	l5_proto=DHCP() or DNS()... (maybe)

TCP():
	source 
	destination
	l5_proto=HTTP() or FTP()... (maybe)
	secured
	data_up
	data_down
`

## Implementation Specific
* We can have a top level dictionary that can be keyed as mentioned above
* It can be wrapped in a class and certain methods can be developed. E.g. converting our data structure to JSON
* Speaking of fields within each connection, it can also be wrapped inside a class or can be kept raw as seen above
* Wrapping them inside another class means for conversion to JSON we have to implement "DFS" like calls i.e. call JSON for every info (if nested)
* If connection specific encapsulation is worth it then we can develop classes or else we can stick to raw key/values

## Things left to do
- [ ] Addressing lower layer protocol keying
- [ ] Thinking about other connections like VPN (yea haven't even touched this)
- [ ] Discussing methods in the top level class
- [x] Whether to use class or raw key/value for connection specific information (Class based)
- [x] Figuring out a way to point to same connection object when source destination swap. The alternate solution in notebook is just a stupid "fix". (Mostly works)
