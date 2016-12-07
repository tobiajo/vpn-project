#!/bin/sh

ee()
{
	echo ">" $@
	eval $@
}

ee "sudo ./udptun -i tun0 -s -d"
