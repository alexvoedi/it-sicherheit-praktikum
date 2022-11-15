# Praktikum IT-Sicherheit WS2022/23

## Projekt: Aufbau einer Toolchain zum automatischen Aufzeichnen, Labeln und Klassifizieren von IoT-Netzwerktraffic

### Gruppe 4 (WLAN-Bridge, Aufzeichnen, Labeln)

#### Anleitung
1) Access point (ap0) erstellen mit https://github.com/lakinduakash/linux-wifi-hotspot
2) `cd src`
3) `sudo ./sniffer.py <packet_count>`

#### Erstellte Dateien
1) `capture.pcap`: Aufgezeichnete Packets
2) `capture.csv`: CSV Datei mit diesen Columns
    * `no`
    * `no_layers`
    * `unix_ts_micro`
    * `mac_src`
    * `mac_dst`
    * `ip_src`
    * `ip_dst`
    * `port_src`
    * `port_dst`
    * `ether_type`
    * `payload_length`
    * `total_length`
3) `config.txt`: Scapy config zum Debuggen
