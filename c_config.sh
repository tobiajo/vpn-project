#!/bin/sh

ee()
{
	echo ">" $@
	eval $@
}

ee "sudo ip addr add 10.0.5.20/24 dev tun0"
ee "sudo ifconfig tun0 up"
ee "sudo route add -net 10.0.10.0 netmask 255.255.255.0 gw 10.0.5.20"
ee "sudo sysctl -w net.ipv4.ip_forward=1"
