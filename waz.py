import argparse
import paramiko


def read_ssh_file(file_path):
    """
    Read a file containing SSH connection strings with PEM file paths.
    Each line in the file should be in the format:
    hostname,username,pem_file_path
    """
    hosts = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(",")
                    if len(parts) == 3:
                        hosts.append((parts[0], parts[1], parts[2]))
    except Exception as e:
        print(f"Error reading file: {e}")
    return hosts


def execute_ssh_command(client, command):
    """Execute an SSH command and return its output."""
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode().strip(), stderr.read().decode().strip()


def get_os_info(client):
    """Detect the OS type and version."""
    commands = [
        "cat /etc/os-release",  # Most Linux distros
        "lsb_release -a",       # Older systems with lsb-release
        "uname -a"              # Fallback
    ]
    for command in commands:
        output, error = execute_ssh_command(client, command)
        if output:
            return output
    raise Exception("Unable to determine OS type and version.")


def install_wazuh_agent(client, os_info, wazuh_server_ip, wazuh_version):
    """Install the Wazuh agent based on the detected OS and configure it to connect to the Wazuh server."""
    if "Blah" in os_info:
        commands = [
            "echo 'Starting Ubuntu Install.......'"
            "export DEBIAN_FRONTEND=noninteractive",
            "export DEBCONF_NONINTERACTIVE_SEEN=true",
            "sudo apt-get update -y",
            "sudo apt-get install -y gnupg2 curl wget",
            "sudo rm -f /etc/apt/sources.list.d/wazuh.list",
            "curl -sO https://packages.wazuh.com/key/GPG-KEY-WAZUH",
            "sudo gpg --dearmor < GPG-KEY-WAZUH | sudo tee /usr/share/keyrings/wazuh.gpg > /dev/null",
            "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main' | sudo tee /etc/apt/sources.list.d/wazuh.list",
            f"wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_{wazuh_version}-1_amd64.deb",
            f"sudo dpkg -i wazuh-agent_{wazuh_version}-1_amd64.deb",
            "sudo systemctl enable wazuh-agent",
            "sudo systemctl start wazuh-agent"
        ]
    if "Ubuntu" or "Debian" in os_info:
        commands = [
            "export DEBIAN_FRONTEND=noninteractive",
            "export DEBCONF_NONINTERACTIVE_SEEN=true",
            "sudo apt-get update -y",
            "sudo apt-get install -y gnupg2 curl wget",
            "sudo rm -f /etc/apt/sources.list.d/wazuh.list",
            "curl -sO https://packages.wazuh.com/key/GPG-KEY-WAZUH && sudo gpg --dearmor < GPG-KEY-WAZUH | sudo tee /usr/share/keyrings/wazuh.gpg > /dev/null",
            "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main' | sudo tee /etc/apt/sources.list.d/wazuh.list",
            f"wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_{wazuh_version}-1_amd64.deb && sudo dpkg -i wazuh-agent_{wazuh_version}-1_amd64.deb",
            f"sudo sed -i 's|<address>.*</address>|<address>{wazuh_server_ip}</address>|' '/var/ossec/etc/ossec.conf'",           
            "sudo systemctl enable wazuh-agent",
            "sudo systemctl start wazuh-agent",
        ]
    elif "CentOS" in os_info or "Red Hat" in os_info or "Fedora" in os_info:
        commands = [
            "sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH",
            "cat <<EOF | sudo tee /etc/yum.repos.d/wazuh.repo\n[wazuh]\nname=Wazuh repository\nbaseurl=https://packages.wazuh.com/4.x/yum/\nenabled=1\ngpgcheck=1\nEOF",
            f"sudo yum install -y wazuh-agent-{wazuh_version}",
            f"sudo sed -i 's|<address>.*</address>|<address>{wazuh_server_ip}</address>|' '/var/ossec/etc/ossec.conf'",
            "sudo systemctl enable wazuh-agent",
            "sudo systemctl start wazuh-agent"
        ]
    else:
        raise Exception(f"Unsupported OS: {os_info}")

    for command in commands:
        output, error = execute_ssh_command(client, command)
        if error:
            print(f"Error: {error}")
        else:
            print(output)


def deploy_to_hosts(hosts, wazuh_server_ip, wazuh_version):
    for hostname, username, pem_file in hosts:
        print(f"\nConnecting to {hostname}...")
        try:
            key = paramiko.RSAKey.from_private_key_file(pem_file)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, pkey=key, timeout=10)

            os_info = get_os_info(client)
            print(f"OS info for {hostname}: {os_info}")

            print(f"Installing Wazuh agent on {hostname}...")
            install_wazuh_agent(client, os_info, wazuh_server_ip, wazuh_version)

            client.close()
            print(f"Installation completed for {hostname}.\n")
        except Exception as e:
            print(f"Error with {hostname}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Deploy Wazuh agent using SSH connections from a file.")
    parser.add_argument("--file", required=True, type=str, help="Path to the file containing SSH connection details.")
    parser.add_argument("--wazuh-server-ip", required=True, type=str, help="IP address of the Wazuh server.")
    parser.add_argument("--wazuh-version", required=True, help="Wazuh Manager version to install the matching agent")
    args = parser.parse_args()

    hosts = read_ssh_file(args.file)
    if not hosts:
        print("No valid hosts found in the file.")
        return

    deploy_to_hosts(hosts, args.wazuh_server_ip, args.wazuh_version)


if __name__ == "__main__":
    main()

"""

    if "Ubuntu" in os_info:
        commands = [
            "echo 'Starting Ubuntu Install.......'"
            "export DEBIAN_FRONTEND=noninteractive",
            "export DEBCONF_NONINTERACTIVE_SEEN=true",
            "sudo apt-get update -y",
            "sudo apt-get install -y gnupg2 curl wget",
            "sudo rm -f /etc/apt/keyrings/wazuh.gpg",
            "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo tee /etc/apt/keyrings/wazuh.gpg > /dev/null",
            "sudo chmod 644 /etc/apt/keyrings/wazuh.gpg",
            "echo 'deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | sudo tee /etc/apt/sources.list.d/wazuh.list",
            "sudo apt update -y",
            "sudo apt remove wazuh-agent -y",
            f"sudo apt install -y wazuh-agent-{wazuh_version} < /dev/null",
            f"sudo sed -i 's|<address>.*</address>|<address>{wazuh_server_ip}</address>|' '/var/ossec/etc/ossec.conf'",
            "sudo chown -R wazuh:wazuh /var/ossec",
            "sudo chmod -R 750 /var/ossec",
            "sudo systemctl daemon-reload",
            "sudo systemctl enable wazuh-agent",
            "sudo systemctl start wazuh-agent"
        ]
    if "Debian" in os_info:
        commands = [
            "export DEBIAN_FRONTEND=noninteractive",
            "export DEBCONF_NONINTERACTIVE_SEEN=true",
            "sudo rm -f /etc/apt/keyrings/wazuh.gpg",
            "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo tee /etc/apt/keyrings/wazuh.gpg > /dev/null",
            "sudo chmod 644 /etc/apt/keyrings/wazuh.gpg",
            "echo 'deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | sudo tee /etc/apt/sources.list.d/wazuh.list",
            "sudo apt-get update -y || { echo 'Failed to update package lists!'; exit 1; }",
            "sudo apt-get remove wazuh-agent -y",
            f"sudo apt-get install -y wazuh-agent-{wazuh_version} < /dev/null",
            f"sudo sed -i 's|<address>.*</address>|<address>{wazuh_server_ip}</address>|' '/var/ossec/etc/ossec.conf'",
            "sudo chown -R wazuh:wazuh /var/ossec",
            "sudo chmod -R 750 /var/ossec",
            "sudo systemctl daemon-reload",
            "sudo systemctl enable wazuh-agent",
            "sudo systemctl start wazuh-agent"
        ]

"""


