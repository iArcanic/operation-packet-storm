# pcap-files Directory

This directory is intended to store the packet capture file (`packet-storm.pcap`) needed for the packet analyser, provided by CoreTech security.

Due to size contraints, this file has been ommitted since GitHub's file size limits are up to 100MB.

## Instructions

1. Download the `packet-storm.pcap` file from the following link:
   [https://github.com/CoreTechSecurity/packet-storm/releases/download/1.0.0/packet-storm.pcap](https://github.com/CoreTechSecurity/packet-storm/releases/download/1.0.0/packet-storm.pcap)

2. Place the downloaded `packet-storm.pcap` file in this directory (`pcap-files`):

```bash
mv <PATH-TO-DOWNLOAD>/packet-storm.pcap <PATH-TO-GIT-REPO>/operation-packet-storm/pcap-files/
```

The project will now therefore use this file automatically when running the Docker container.
