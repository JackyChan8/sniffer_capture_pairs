import argparse
from scapy.all import *
from binascii import hexlify
from termcolor import colored


def print_information(packet_info: dict[str, bytes]) -> None:
    """Output Information to Console"""
    print(f"""
    \r{colored('DATA: ', 'blue', attrs=['bold'])} {colored(str(packet_info.get("data")), 'yellow')}
    
    \r{colored('HEX: ', 'blue', attrs=['bold'])} {colored(str(packet_info.get("hex")), 'yellow')}
    \r{colored('==================================================================================', 'green')}
    """)


def check_is_raw(packet_obj: Packet) -> None:
    """Check in Packet Raw"""
    if packet_obj.haslayer(Raw):
        data_packet = packet_obj[Raw].load
        hex_packet = hexlify(data_packet)
        print_information({'data': data_packet, 'hex': hex_packet})


def sniffer(iface: str, ip: str, port: int) -> None:
    """Sniffer"""
    sniff(
        iface=iface,
        filter=f'tcp and dst {ip} or src {ip} and port {port}',
        prn=lambda x: check_is_raw(x)
    )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Sniffer Interface")
    parser.add_argument('-iface', dest='iface', required=True, help='Interface to perform capture')
    parser.add_argument('-ip', dest='ip', required=True, help='IP to filter packets for')
    parser.add_argument('-port', dest='port', required=False, type=int, help='Port to capture packets on')

    args = parser.parse_args()
    sniffer(args.iface, args.ip, args.port)
