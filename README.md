# WazuhAuto 

WazuhAuto is an automated Python project that automates Wazuh deployment.

WazuhAuto automates the deployment of the Wazuh XDR and SIEM agent to Linux machines by leveraging saved PuTTY profiles in Windows. The script connects to the Linux hosts via SSH, detects the operating system and version, configures the appropriate repository, and installs the Wazuh agent.

## Features

- Extracts PuTTY connection profiles from the Windows Registry.
- Connects to Linux hosts using SSH.
- Automatically detects the operating system type and version.
- Configures the Wazuh repository and installs the Wazuh agent.
- Supports deployment to a single host or all saved PuTTY profiles.

## Prerequisites

- **Windows OS** with PuTTY installed and connection profiles saved.
- **Python 3.x** installed on the machine running the script.
- The following Python libraries:
  - `paramiko`
  - `winreg` (comes with Python on Windows)

Install the required libraries using the provided `requirements.txt` file.

## Supported Operating Systems for Wazuh Deployment

The script supports the following Linux distributions:

- Debian-based systems (e.g., Ubuntu, Debian)
- Red Hat-based systems (e.g., CentOS, RHEL, Fedora)

## Installation

1. Clone or download this repository.
2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt

## Usage


   
