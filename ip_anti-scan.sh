#!/bin/bash

## Author : xephoxx
## Date : 2018/04/22
## Purpose : Avoid SCAN via iptables
## Company : NeosLab

### Notions on security :
# Here it is very simple, but it is also essential. Due to the multitude of possibilities that exist and to avoid creating breaches, everything is forbidden by default.
# And then you allow what needs to be permitted... The thing you can see here is that you adopt a "policy" to apply to all connections (prohibit everything), that you refine with specific rules.

# We will start, as indicated in the notions of security, by prohibiting everything :
# So no connection is allowed, and nothing is permitted !
iptables -t filter -P INPUT DROP
iptables -t filter -P FORWARD DROP
iptables -t filter -P OUTPUT DROP

# If we have servers using the same machine
iptables -t filter -A OUTPUT -o lo -j ACCEPT
iptables -t filter -A INPUT -i lo -j ACCEPT

# First, we have to allow DNS server exchanges :
iptables -t filter -A OUTPUT -p udp -m udp --dport 53 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -p udp -m udp --sport 53 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Useful for basic navigation:
# 80 = HTTP ; 443 = HTTPS
iptables -t filter -A OUTPUT -p tcp -m multiport --dports 80,443,8000,8080 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -p tcp -m multiport --sports 80,443,8000,8080 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Block icmp responses
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Allow NTP (eg client)
iptables -A INPUT -i lo -p udp --dport 123 -j ACCEPT
iptables -A INPUT -p udp --sport 123:123 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o lo -p udp --sport 123 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123:123 -m state --state NEW,ESTABLISHED -j ACCEPT

# Allow outgoing SSH only to a specific network
#iptables -A OUTPUT -o eth0 -p tcp -d 192.168.101.0/24 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -i eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

#  Allow incoming SSH only from a specific network
#iptables -A INPUT -i eth0 -p tcp -s 192.168.200.0/24 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# Allow SSH (eg serveur)
#iptables -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# Allow SSH (eg client)
iptables -A OUTPUT -o eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

### Below are iptables rules to detect a scan attempt (generally at most specific) :
# For some options, if you don't understand I invite you to go to the documentation on the website or read the man.

# NULL-SCAN detection
iptables -t filter -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "IPTABLES NULL-SCAN:"
iptables -t filter -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# XMAS-SCAN detection
iptables -t filter -A INPUT -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "IPTABLES XMAS-SCAN:"
iptables -t filter -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# SYNFIN-SCAN detection
iptables -t filter -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j LOG --log-prefix "IPTABLES SYNFIN-SCAN:"
iptables -t filter -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j DROP

# NMAP-XMAS-SCAN detection
iptables -t filter -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j LOG --log-prefix "IPTABLES NMAP-XMAS-SCAN:"
iptables -t filter -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j DROP

# FIN-SCAN detection
iptables -t filter -A INPUT -p tcp --tcp-flags ALL FIN -j LOG --log-prefix "IPTABLES FIN-SCAN:"
iptables -t filter -A INPUT -p tcp --tcp-flags ALL FIN -j DROP

# NMAP-ID detection
iptables -t filter -A INPUT -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -j LOG --log-prefix "IPTABLES NMAP-ID:"
iptables -t filter -A INPUT -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -j DROP

# SYN-RST detection
iptables -t filter -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "IPTABLES SYN-RST:"
iptables -t filter -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# SYN-FLOODING detection
iptables -t filter -N syn-flood
iptables -t filter -A INPUT -i eth0 -p tcp --syn -j syn-flood
iptables -t filter -A syn-flood -m limit --limit 1/sec --limit-burst 4 -j RETURN
iptables -t filter -A syn-flood -j LOG --log-prefix "IPTABLES SYN-FLOOD:"
iptables -t filter -A syn-flood -j DROP

# Make sure NEW tcp connections are SYN packets 
iptables -t filter -A INPUT -i eth0 -p tcp ! --syn -m state --state NEW -j LOG  --log-prefix "IPTABLES SYN-FLOOD:"
iptables -t filter -A INPUT -i eth0 -p tcp ! --syn -m state --state NEW -j DROP

# Port scanner detection
iptables -t filter -N port-scan
iptables -t filter -A INPUT -i eth0 -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j port-scan
iptables -t filter -A port-scan -m limit --limit 1/s --limit-burst 4 -j RETURN
iptables -t filter -A port-scan -j LOG --log-prefix "IPTABLES PORT-SCAN:"
iptables -t filter -A port-scan -j DROP
