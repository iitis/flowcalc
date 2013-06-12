#!/bin/bash

MYDIR=`dirname $0`

$MYDIR/../pcap2ip/pcap2ip.py | flowcalc -e counters,basic,pktsize,dns,lpi,coral -
