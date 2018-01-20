# firewall

========

Bash script to use iptables (and ip6tables) to allow specifics rules.
The config file wich contains the rules should be put at /etc/default/firewall-config.
It can be override in firewall.service file or even better in /etc/systemd/system/firewall.service.d/local.conf
Test on Debian 8.10+

## Installation

### TODO

## Usage

Just uncomment the rule in firewall-config to apply.
It's highly recommend to whitelist your IP in the configuration file and avoid being kicked out of the system.

### Rules available

```bash
LOCAL_ACCEPT
ICMP
DNS_BASIC
NTP
HTTP_OUTPUT
ALLOW_SSH
ALLOW_FTP
SMTP_OUTPUT
SMTP_INPUT
POP3
IMAP
OPENVPN
FLOOD
PROXMOX_WEB
LOG
DNS_OPENNIC
DOCKER
BLOCK_SSH
BLOCK
FAIL2BAN
```
