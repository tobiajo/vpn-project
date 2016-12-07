#!/bin/sh

ee()
{
	echo ">" $@
	eval $@
}

ee "sudo ./udptun -i tun0 -c 192.168.10.5 -d"
