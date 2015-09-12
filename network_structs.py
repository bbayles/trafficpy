from struct import Struct

ethernet_header = Struct(
    '!'  # Network order
    '6s'  # Source MAC address
    '6s'  # Destination MAC address
    'H'  # Ethertype
)

ipv4_header = Struct(
    '!'  # Network order
    'c'  # Version / IHL
    'c'  # DSCP / ECN
    'H'  # Total length
    '2s'  # Identification
    '2s'  # Flags / Fragment offset
    'B'  # Time to live
    'B'  # Protocol
    'H'  # Header checksum
    '4s'  # Source IP address
    '4s'  # Destination IP address
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
