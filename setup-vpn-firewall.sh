#!/bin/bash

iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -A INPUT -i tun0 -j ACCEPT
iptables -A OUTPUT -o tun0 -j ACCEPT

iptables -A FORWARD -i tun0 -o enp0s3 -s 10.0.0.0/24 -j ACCEPT
iptables -A FORWARD -i enp0s3 -o tun0 -d 10.0.0.0/24 -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 1194 -j ACCEPT

iptables -t nat -A POSTROUTING -o enp0s3 -s 10.0.0.0/24 -j MASQUERADE

iptables -A INPUT -j DROP

sysctl -w net.ipv4.ip_forward=1

echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

iptables-save > /etc/iptables/rules.v4

echo "Completed!"
