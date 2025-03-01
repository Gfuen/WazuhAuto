# WazuhAuto Project

## Overview
This project automates the deployment of the Wazuh agent on Linux servers using SSH PEM private keys. The script takes a list of servers, connects to each via SSH, detects the operating system, and installs the appropriate version of the Wazuh agent.

## Features
- Automated Wazuh agent installation on Linux servers
- OS detection to ensure correct installation commands
- Configuration of the agent to communicate with the Wazuh Manager
- Supports Ubuntu, Debian, CentOS, Red Hat, and Fedora
- Uses SSH with private key authentication

## Prerequisites
- Python 3 installed
- `paramiko` library installed (`pip install paramiko`)
- A list of Linux servers with SSH access using a PEM key
- Wazuh Manager IP address
- Wazuh agent version to install

## Installation
1. **Clone the Repository:**
```
git clone https://github.com/Gfuen/WazuhAuto.git
cd wazuh-deployment
```

2. **Install the Dependencies:**
```
pip install -r requirements.txt
```

## Usage

1. **Prepare the SSH Hosts file**

Create a text file (e.g., hosts.txt) with the format:
```
server1.example.com,username,/path/to/private-key.pem
server2.example.com,username,/path/to/private-key.pem
```

Each line contains:
- Hostname or IP
- SSH Username (User should have sudo privileges)
- Path to the private key
2. **Run the Script**

Execute the script using:
```
python deploy_wazuh.py --file hosts.txt --wazuh-server-ip <WAZUH_SERVER_IP> --wazuh-version <WAZUH_VERSION>
```
Example:
```
python deploy_wazuh.py --file hosts.txt --wazuh-server-ip 192.168.1.100 --wazuh-version 4.4.0
```

## Supported Operating Systems

- Ubuntu
- Debian
- RHEL

## Troubleshooting

- Ensure the PEM file has correct permissions (chmod 400 <private-key.pem>).
- Verify SSH connectivity to the target servers.
- Ensure the provided Wazuh agent version is available for the OS and is the same version as the Wazuh manager version.

## Contact

Let me know if you need any modifications by opening an issue ticket or reaching out for questions/concerns. Thanks.
