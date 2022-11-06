# Praktikum IT-Sicherheit WS2022/23

## Projekt: Aufbau einer Toolchain zum automatischen Aufzeichnen, Labeln und Klassifizieren von IoT-Netzwerktraffic

### Gruppe 4 (WLAN-Bridge, Aufzeichnen, Labeln)

#### Anleitung
1) Access point (ap0) erstellen mit https://github.com/lakinduakash/linux-wifi-hotspot
2) `cd src`
3) `sudo sniffer.py`

#### Erstellte Dateien
1) `capture.pcap`: Aufgezeichnete Packets
2) `capture.csv`: Mapping Packetnr. -> Klasse (0: normal, 1: Interaktion, 2: Angriff)
3) `config.txt`: Scapy config zum Debuggen