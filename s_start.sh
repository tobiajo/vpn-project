#!/bin/sh

ee()
{
	echo ">" $@
	eval $@
}

ee "sudo ./udptun2 -i tun0 -s -d"
