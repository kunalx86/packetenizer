# Web Interface
	- Should include a form to upload .pcap or .pcapng file to the server.
	- Should be able to display the analyzed information in a clean format and human readable.

# Web Server
	- Should expose APIs to upload .pcap files and get analyzed information.
	- Should act as a wrapper to the core module.

# Parser
	- Parse the file and represent the packets in some internal data structures.
	- Already implemented in Python. E.g. DPKT, Scapy, Pypcapkit.

# Analyzer
	- Analyze the parsed packets and derive conclusions.
	- Record among other things amount of data transferred between various connections.
	- List various hosts communicated to.
	- List possible D/DOS attemps.
	- List un intended connections. E.g. Someone trying to SSH into a server when he/she really shouldn't.


## References
  - https://pypi.org/project/pypcapkit/
  - https://scapy.net/
  - https://apackets.com
  - https://dpkt.readthedocs.io/en/latest/
  - https://jon.oberheide.org/blog/2008/08/25/dpkt-tutorial-1-icmp-echo/