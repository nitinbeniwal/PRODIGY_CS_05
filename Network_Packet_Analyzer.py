
import socket
import struct
import textwrap


def format_multi_line(data, size=80):
    return '\n'.join([data[i:i+size] for i in range(0, len(data), size)])


def start_packet_sniffer():
    
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
       
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f"\nEthernet Frame:\nDestination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

      
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(f"IPv4 Packet:\nVersion: {version}, Header Length: {header_length}, TTL: {ttl}")
            print(f"Protocol: {proto}, Source IP: {src}, Destination IP: {target}")

         
            if proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flags, data) = tcp_segment(data)
                print(f"TCP Segment:\nSource Port: {src_port}, Destination Port: {dest_port}")
                print(f"Sequence: {sequence}, Acknowledgment: {acknowledgment}")
                print(f"Flags: {flags}")
                print(f"Data:\n{format_multi_line(data)}")


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))


def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    return src_port, dest_port, sequence, acknowledgment, offset_reserved_flags, data[14:]

if __name__ == "__main__":
    print("Starting Packet Sniffer... Press 'Ctrl + C' to stop.")
    start_packet_sniffer()
