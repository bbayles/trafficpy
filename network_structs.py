from struct import Struct

ethernet_header = Struct(
    '!'  # Network order
    '6s'  # Destination MAC address
    '6s'  # Source MAC address
    'H'  # Ethertype
)


ethernet_q_header = Struct(
    '!'  # Network order
    '6s'  # Destination MAC address
    '6s'  # Source MAC address
    'H'  # TPID
    'H'  # TCI
    'H'  # Ethertype
)


ethernet_qq_header = Struct(
    '!'  # Network order
    '6s'  # Destination MAC address
    '6s'  # Source MAC address
    'H'  # Outer TPID
    'H'  # Outer TCI
    'H'  # Inner TPID
    'H'  # Inner TCI
    'H'  # Ethertype
)


sll_header = Struct(
    '!'  # Network order
    'H'  # Packet type
    'H'  # ARPHRD_ type
    'H'  # Link-layer address length
    '8s'  # MAC address
    'H'  # Ethertype
)


ipv4_header = Struct(
    '!'  # Network order
    'c'  # Version / IHL
    'c'  # DSCP / ECN
    'H'  # Total length
    'H'  # Identification
    'H'  # Flags / Fragment offset
    'B'  # Time to live
    'B'  # Protocol
    'H'  # Header checksum
    '4s'  # Source IP address
    '4s'  # Destination IP address
)


ipv6_header = Struct(
    '!'  # Network oder
    '4s'  # Version, Traffic class, Flow label
    'H'  # Payload length
    'B'  # Next Header
    'c'  # Hop limit
    '16s'  # Source IP address
    '16s'  # Destination IP address
)

tcp_header = Struct(
    '!'  # Network order
    'H'  # Source port
    'H'  # Destination port
    'I'  # Sequence number
    'I'  # Acknowledgment number
    '2s'  # Data offset, Reserved, Flags
    'H'  # Window Size
    'H'  # Checksum
    'H'  # Urgent pointer
)

udp_header = Struct(
    '!'  # Network order
    'H'  # Source port
    'H'  # Destination port
    'H'  # Length
    'H'  # Checksum
)

icmp_header = Struct(
    '!'  # Network order
    'H'  # Type / Code
    'H'  # Checksum
    '4s'  # Rest of Header
)
