#!/usr/bin/env python

import os

from scapy.config import conf
from scapy.sendrecv import sniff
from scapy.utils import PcapWriter


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


# Currently a dummy function to generate the (hopefully) correct .csv schema
def write_csv(fname, cptr):
    with open(fname, "w") as f:
        f.write("packet_number,traffic_class\n")
        for _, packet_num in zip(cptr, range(1, len(cptr) + 1)):
            f.write(f"{packet_num},0\n")
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
                    count=50)
    # Write captured packets
    write_pcap("capture.pcap", capture)
    # Write traffic classification mapping
    write_csv("capture.csv", capture)
    # Dump config for debugging
    dump_config("config.txt")


if __name__ == '__main__':
    main()
