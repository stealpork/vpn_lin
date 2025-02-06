#!/bin/bash

VPN_INTERFACE="tun1"              
VPN_SERVER_IP="10.0.2.15"          
VPN_SUBNET="255.255.255.0/24"          
LOCAL_NETWORK="10.0.2.4/24"   
DEFAULT_GATEWAY="10.0.2.1" 
DEFAULT_ROUTE_METRIC=100        



sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

ip link set $VPN_INTERFACE up

ip route flush table main

ip route del default

ip route add default via $VPN_SERVER_IP dev $VPN_INTERFACE metric $DEFAULT_ROUTE_METRIC
sudo ip route add default dev tun1

ip route show

iptables -t nat -A POSTROUTING -o $VPN_INTERFACE -s $VPN_SUBNET -j MASQUERADE

iptables -A FORWARD -i $VPN_INTERFACE -o enp0s3 -s $VPN_SUBNET -j ACCEPT
iptables -A FORWARD -i enp0s3 -o $VPN_INTERFACE -d $VPN_SUBNET -j ACCEPT

ip route add $LOCAL_NETWORK via $DEFAULT_GATEWAY


iptables-save > /etc/iptables/rules.v4


echo "Completed!"
