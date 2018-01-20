#!/bin/bash

####### All Firewall rules #######
##################################

## TODO
# Allow traffic from a withelist ip with ipset
# OPENVPN() Personnalize private network
# CLAMAV()
# DOCKER Find some better rules

# DEFAULT_CONF='/etc/default/firewall-config'

# Some basic checks
CHECK() {
  # Config file
  if [ ! -f $DEFAULT_CONF ]; then
    echo "Can NOT find configuration file ( $DEFAULT_CONF )";
    exit 1;
  fi

  # Backup rules
  if [ ! -f "$HOME/iptables-default" ] ; then
    /sbin/iptables-save > $HOME/iptables-default ;
  fi

  if [ ! -f "$HOME/ip6tables-default" ] ; then
    /sbin/ip6tables-save > $HOME/ip6tables-default ;
  fi

  # Use IPv6
  if ping6 -c 1 debian.org >/dev/null 2>&1; then
    IPV6='yes';
  else
    IPV6='no';
  fi

}


## For both IPv4 and IPv6 rules
IPTABLES() {
  local statement="$(echo ${1})"
  if [[ "$IPV6" = 'yes' ]]; then
    eval /sbin/ip6tables $statement;
  fi
  eval /sbin/iptables $statement;
}

## FONCTION RESULTL()
# Each function initialize result=0
# If one command failed, $result is set to "1"
RESULTL(){

	if [ $1 -eq 0 ] ; then
		echo -e "$2 : [ "OK" ]";
	else
		echo -e "$2 : [ "FAILED" ]";
	fi
}

##################################
##################################

# OPEN DOORS
FLUSH() {
  result="0" ;
  IPTABLES "-t filter -F" || result="1" ;
  IPTABLES "-t filter -X" || result="1" ;
  /sbin/iptables -t nat -F || result="1" ;
  RESULTL $result "Flushing rules.."
}


# ACCEPT FORWARD
FORWARD() {
  result="0" ;
  IPTABLES "-t filter -P FORWARD ACCEPT" || result="1" ;
  RESULTL $result "Allow Forward.."
}


# ACCEPT ESTABLISHED AND LOCALHOST
LOCAL_ACCEPT() {
  result="0" ;
  IPTABLES "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT" || result="1" ;
  IPTABLES "-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A INPUT -i lo -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A OUTPUT -o lo -j ACCEPT" || result="1" ;
  RESULTL $result "Allow localhost access and related connections.."
}


# ICMP (Ping)
# BLOCK incoming ICMP on IPv4 but allow outgoing request
ICMP() {
  result="0" ;
  # /sbin/iptables -t filter -A INPUT -p icmp -j ACCEPT || result="1" ;
  /sbin/iptables -t filter -A OUTPUT -p icmp -m state --state NEW -j ACCEPT || result="1" ;

  # IPv6
  if [[ "$IPV6" -eq 0 ]]; then
    /sbin/ip6tables -t filter -A INPUT -p ipv6-icmp -j ACCEPT || result="1" ;
    /sbin/ip6tables -t filter -A OUTPUT -p ipv6-icmp -j ACCEPT || result="1" ;
  fi

  RESULTL $result "Allow ping.."
}


# SSH
ALLOW_SSH() {
  result="0" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 22 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 22 -j ACCEPT" || result="1" ;
  RESULTL $result "Allow SSH.."
}


# NTP (horloge du serveur)
NTP() {
  result="0" ;
  IPTABLES "-t filter -A OUTPUT -p udp --dport 123 -j ACCEPT" || result="1" ;
  RESULTL $result "Allow NTP.."
}


# DNS REQUEST
DNS_BASIC() {
  result="0" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT" || result="1":
  IPTABLES "-t filter -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT" || result="1":
  RESULTL $result "Allow BASIC DNS queries.."
}


## HTTP/HTTPS
# INPUT
HTTP_INPUT() {
  result="0" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT"  || result="1" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT"  || result="1" ;
  RESULTL $result "Allow connections for HTTP(s) outside.."
}


# OUPUT
HTTP_OUTPUT() {
  result="0" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT" || result="1" ;
  RESULTL $result "Allow connections for HTTP(s) from inside.."
}


# FTP
ALLOW_FTP() {
  result="0" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 20:21 -m state --state NEW -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 20:21 -m state --state NEW -j ACCEPT" || result="1" ;
  RESULTL $result "Allow connections for FTP Server.."
}


## Mail
# SMTP OUTPUT
SMTP_OUTPUT() {
  result="0" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 465 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 587 -j ACCEPT" || result="1" ;
  RESULTL $result "Allow connections for SMTP Server.."
}


# SMTP INPUT
SMTP_INPUT() {
  result="0" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 25 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 465 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 587 -j ACCEPT" || result="1" ;
  RESULTL $result "Allow connections for SMTP Server.."
}


# POP3 / POP3s
POP3() {
  result="0" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 110 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 110 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 995 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 995 -j ACCEPT" || result="1" ;
  RESULTL $result "Allow connections for POP3 server.."
}


# Mail IMAP / IMAPs
IMAP() {
  result="0" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 143 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 143 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 993 -j ACCEPT" || result="1" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 993 -j ACCEPT" || result="1" ;
  RESULTL $result "Allow connections for IMAP Server.."
}

# For OpenVPN
OPENVPN() {
  result="0" ;
  # Assuming 10.8.0.0/24 is your private network
  /sbin/iptables -A INPUT -i eth0 -p all -s 10.8.0.0/24 -j ACCEPT || result="1" ;
  /sbin/iptables -A OUTPUT -o eth0 -p all -d 10.8.0.0/24 -j ACCEPT || result="1"
  # Relay to Internet
  IPTABLES "-t nat -A POSTROUTING -o eth0 -j MASQUERADE" || result="1" ;
  IPTABLES "-t nat -A POSTROUTING -o tun+ -j MASQUERADE" || result="1" ;
  RESULTL $result "Allow connections for OpenVPN Server and NAT POSTROUTING.."
  systemctl openvpn restart && echo "OpenVPN restarted" ;
}

# Flood & DDOS
FLOOD() {
  result="0" ;
  IPTABLES "-A FORWARD -p udp -m limit --limit 1/second -j ACCEPT" || result="1" ;
  /sbin/iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT || result="1" ;
  # TODO for ipv6
  #/sbin/ip6tables -A FORWARD -p ipv6-icmp --icmpv6-type echo-request -m limit --limit 1/second -j ACCEPT || result="1" ;
  # Port scan
  IPTABLES "-A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT" || result="1" ;
  RESULTL $result "Try to block DDOS, flood and nmap.."
}


# PROMOX
PROXMOX_WEB() {
  result="0" ;
  IPTABLES "-t filter -A INPUT -p tcp --dport 8006 -m state --state NEW -j ACCEPT" || result="1" ;
  RESULTL $result "Allow connections for PROMOX.."
}


# LOG
LOG() {
result="0" ;
  IPTABLES "-A INPUT -m limit --limit 5/min -j LOG --log-prefix 'IPTables_INPUT' --log-level 4" || result="1" ;
  IPTABLES "-A OUTPUT -m limit --limit 5/min -j LOG --log-prefix 'IPTables_OUPUT' --log-level 4" || result="1" ;
  IPTABLES "-A FORWARD -m limit --limit 5/min -j LOG --log-prefix 'IPTables_FORWARD' --log-level 4" || result="1" ;
  RESULTL $result "Loggin for firewall activated.."
}

## Block everything else
# !! BECAREFUL !!
# Be sure you have withelist your IP or
# YOU WILL NOT BE ABLE TO CONNECT TO YOUR SERVER !
BLOCK() {
  result="0" ;
  IPTABLES "-t filter -P INPUT DROP" || result="1" ;
  IPTABLES "-t filter -P OUTPUT DROP" || result="1" ;
  #IPTABLES -t filter -P FORWARD DROP || result="1" ;
  RESULTL $result "Block everything else.."
}


# Reset / Accept everything
AUTHORIZED_ALL() {
  result="0" ;
  FLUSH ;
  IPTABLES "-t filter -P INPUT ACCEPT" || result="1" ;
  IPTABLES "-t filter -P OUTPUT ACCEPT" || result="1" ;
  #IPTABLES "-t filter -P FORWARD ACCEPT" || result="1" ;
  rm /run/firewall.lock ;
  RESULTL $result "Accept all connections.."
}


# Or restore default configuration
RESTORE_DEF() {
  result="0";
  test -r $HOME/iptables-default && \
    /sbin/iptables-restore < $HOME/iptables-default || result='1' ;
  test -r $HOME/ip6tables-default && \
    /sbin/ip6tables-restore < $HOME/ip6tables-default || result='1' ;
  RESULTL $result "Restore default configuration.."
}

# Some program should be (re)start
FAIL2BAN() {
  systemctl fail2ban restart && echo "Fail2ban rules restarted" ;
}


## OpenNIC DNS Servers
# Rules can be use for any public DNS servers
# It slow down queries to prevent DNS Amplification attack
# See : https://wiki.opennic.org/opennic/tier2security
DNS_OPENNIC() {
  result="0" ;
  # Limit to 30 query / min
  IPTABLES "-A INPUT -p udp -m hashlimit --hashlimit-srcmask 24 --hashlimit-mode srcip --hashlimit-upto 80/m --hashlimit-burst 80 --hashlimit-name DNSTHROTTLE --dport 53 -j ACCEPT "|| result="1" ;
  IPTABLES "-A INPUT -p tcp -m hashlimit --hashlimit-srcmask 24 --hashlimit-mode srcip --hashlimit-upto 80/m --hashlimit-burst 80 --hashlimit-name DNSTHROTTLE --dport 53 -j ACCEPT "|| result="1" ;
  # To protect against floods from queries for isc.org
  IPTABLES "-A INPUT -p udp -m string --hex-string '|00000000000103697363036f726700|' --algo bm --to 65535 --dport 53 -j DROP" || result="1" ;
  # To protect against floods from queries for ripe.net:
  IPTABLES "-A INPUT -p udp -m string --hex-string '|0000000000010472697065036e6574|' --algo bm --to 65535 --dport 53 -j DROP" || result="1" ;
  # To limit ANY queries per IP address, use these two lines:
  IPTABLES "-A INPUT -p udp --dport 53 -m string --from 50 --algo bm --hex-string '|0000FF0001|' -m recent --set --name dnsanyquery" || result="1" ;
  IPTABLES "-A INPUT -p udp --dport 53 -m string --from 50 --algo bm --hex-string '|0000FF0001|' -m recent --name dnsanyquery --rcheck --seconds 60 --hitcount 4 -j DROP" || result="1" ;
  IPTABLES "-A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT" || result="1" ;
  IPTABLES "-A OUTPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT" || result="1" ;
  RESULTL $result "Allow connections for DNS OpenNIC.."
}


# For CLAMAV UPDATES
# OLD RULES ?
# CLAMAV() {
#   result="0" ;
#   /sbin/iptables -t filter -A OUTPUT -p tcp -d 46.29.125.16 -j ACCEPT || result="1" ;
#   /sbin/iptables -t filter -A OUTPUT -p tcp -d 178.32.100.7 -j ACCEPT || result="1" ;
#   RESULTL $result "Allow connections fot ClamAV updates.."
# }


## DOCKER
# IPV4 only
# Adapt according to your configuration
DOCKER() {
  result="0" ;
  /sbin/iptables -t nat -A PREROUTING -j ACCEPT || result="1";
  /sbin/iptables -t nat -A INPUT -j ACCEPT || result="1";
  /sbin/iptables -t nat -A OUTPUT -j ACCEPT || result="1";
  /sbin/iptables -t nat -A POSTROUTING -s 10.190.33.0/24 ! -o docker0 -j MASQUERADE || result="1";
  /sbin/iptables -t nat -A POSTROUTING -s 172.0.0.0/8 -j MASQUERADE || result="1";
  /sbin/iptables -t filter -A FORWARD -i docker0 ! -o docker0 -j ACCEPT || result="1";
  /sbin/iptables -t filter -A FORWARD -i docker0 -o docker0 -j ACCEPT || result="1";
  /sbin/iptables -t filter -A FORWARD -m conntrack --ctstate  ESTABLISHED,RELATED -j ACCEPT || result="1";
  /sbin/iptables -t nat -A POSTROUTING -j ACCEPT || result="1";
  /sbin/iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE || result="1";
  /sbin/iptables -t filter -A OUTPUT -s 172.0.0.0/8 -p tcp -j ACCEPT || result="1";
  RESULTL $result "Allow Docker..."
}


## BLOCK SSH
# !! BECAREFUL !!
# Be sure you have withelist your IP or
# YOU WILL NOT BE ABLE TO CONNECT TO YOUR SERVER !
BLOCK_SSH() {
  result="0" ;
  IPTABLES "-t filter -A INPUT -p tcp --sport 22 -j DROP" || result="1";
  IPTABLES "-t filter -A OUTPUT -p tcp --dport 22 -j DROP" || result="1";
  RESULTL $result "Block SSH...";
}

WHITELIST_IPV4() {
  /sbin/iptables -I INPUT -s $CONNECTION_IP4 -j ACCEPT || result="1" ;
  /sbin/iptables -I OUTPUT -d $CONNECTION_IP4 -j ACCEPT || result="1" ;
  RESULTL $result "Whitelist IPv4 $CONNECTION_IP4...";
}

WHITELIST_IPV6() {
  /sbin/ip6tables -I INPUT -s $CONNECTION_IP6 -j ACCEPT || result="1" ;
  /sbin/ip6tables -I OUTPUT -d $CONNECTION_IP6 -j ACCEPT || result="1" ;
  RESULTL $result "Whitelist IPv6 $CONNECTION_IP6...";
}

do_stop() {
  # Get back to default rules from $HOME/iptables-default ?
  #RESTORE_DEF

  # OR
  AUTHORIZED_ALL
}

do_start() {
  CHECK;
  test -r $DEFAULT_CONF && . $DEFAULT_CONF

  if [ ! -z $CONNECTION_IP4 ]; then
    WHITELIST_IPV4 $CONNECTION_IP4
  elif [ ! -z CONNECTION_IP6 ]; then
    WHITELIST_IPV6 $CONNECTION_IP6
  fi

  touch /run/firewall.lock ;
}

case $1 in
  start) do_start && echo "Settings rules done."
  ;;
  stop) do_stop && echo "Restoring firewall rules done."
  ;;
  status) iptables -L && iptables -t nat -L
  ;;
  restart) do_stop && do_start && echo "Settings rules done."
  ;;
  *) echo " use start|stop|status - Flushing rules is automatic"
  ;;
esac
