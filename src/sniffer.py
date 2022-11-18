#!/usr/bin/env python

import os
import sys

from scapy.all import conf, sniff, PcapWriter


packet_counter = 0


def packet_callback(_):
    global packet_counter
    packet_counter += 1
    print(f"Captured {packet_counter:8} packets.")


def get_bpf_filter():
    return " ".join([
        # EtherType blacklist:
        # 0x88e1 == Homeplug AV
        # 0x8912 == Unknown
        "not (ether proto 0x88e1 or ether proto 0x8912)",
        "and",
        # MAC address whitelist:
        "ether host 80:4E:70:13:01:8A",
    ])


def write_pcap(fname, cptr):
    pcap_writer = PcapWriter(fname, linktype=None, nano=True)
    pcap_writer.write(cptr)
    os.chown(fname, 1000, 1000)


def write_csv(fname, cptr):
    with open(fname, "w") as f:
        # Header
        f.write(
            "no,no_layers,unix_ts_micro,mac_src,mac_dst,ip_src,"
            "ip_dst,port_src,port_dst,ether_type,payload_length,total_length\n"
        )

        for packet, packet_no in zip(cptr, range(1, len(cptr) + 1)):
            pckt_no_layers = len(packet.layers())  # Number of layers
            pckt_unix_ts_micro = int(packet.time * 1000000)  # Unix TS in microseconds
            pckt_mac_src = packet.src if hasattr(packet, "src") else "NULL"  # Source mac address
            pckt_mac_dst = packet.dst if hasattr(packet, "dst") else "NULL"  # Destination mac address
            pckt_ip_src = packet["IP"].src if hasattr(packet, "IP") else "NULL"  # Source ip address
            pckt_ip_dst = packet["IP"].dst if hasattr(packet, "IP") else "NULL"  # Destination ip address
            pckt_port_src = packet.sport if hasattr(packet, "sport") else "NULL"  # Source port
            pckt_port_dst = packet.dport if hasattr(packet, "dport") else "NULL"  # Destination port
            pckt_ether_type = hex(packet.type) if hasattr(packet, "type") else "NULL"  # EtherType
            pckt_payload_length = len(packet.load)  # Payload packet length
            pckt_total_length = len(packet)  # Total packet length

            # Write row
            f.write(
                f"{packet_no},{pckt_no_layers},{pckt_unix_ts_micro},{pckt_mac_src},"
                f"{pckt_mac_dst},{pckt_ip_src},{pckt_ip_dst},{pckt_port_src},"
                f"{pckt_port_dst},{pckt_ether_type},{pckt_payload_length},{pckt_total_length}\n"
            )

    os.chown(fname, 1000, 1000)


def dump_config(fname):
    with open(fname, "w") as f:
        f.write(str(conf))
    os.chown(fname, 1000, 1000)


def main():
    # Sniff <count> packets on access point interface
    capture = sniff(prn=packet_callback,
                    iface="ap0",
                    filter=get_bpf_filter(),
                    monitor=True,
                    count=int(sys.argv[1]))
    # Write captured packets
    write_pcap("capture.pcap", capture)
    # Write traffic classification mapping
    write_csv("capture.csv", capture)
    # Dump config for debugging
    dump_config("config.txt")


if __name__ == '__main__':
    main()
