#!/bin/bash

# Download necessary files
# and configure private ip in config.yml

curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.14/config.yml

# Generate config files for wazuh-server
bash wazuh-isntall -g

# Install wazuh-server
sudo bash wazuh-install.sh --wazuh-server wazuh-1