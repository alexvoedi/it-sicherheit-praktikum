# Praktikum IT-Sicherheit WS2022/23

## Projekt: Aufbau einer Toolchain zum automatischen Aufzeichnen, Labeln und Klassifizieren von IoT-Netzwerktraffic

### Gruppe 4 (WLAN-Bridge, Aufzeichnen, Labeln)

### Anleitung Webserver

1) `cd src`
2) `./webserver.py`
3) Dateiupload mit `POST` auf Port `8888` (siehe `upload_test.sh` im `test` Verzeichnis)
4) Ankommende Dateien werden abgespeichert mit Dateinamen: Unix-timestamp + alter Dateiname
