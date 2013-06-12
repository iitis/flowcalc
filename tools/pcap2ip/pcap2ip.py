#!/usr/bin/env python
# rewrite pcap files in whatever format to raw IP pcap
# e.g. chop PPPoE headers, etc.

import sys
import dpkt

import reader
import writer

def main():
	rd = reader.Pktsrc("-")
	wr = writer.Writer(sys.stdout, snaplen=65535, linktype=dpkt.pcap.DLT_RAW)

	# for stats
	stat_ok = 0
	stat_dropped = 0

	for pkt in rd:
		try:
			# decode and find IP layer
			ip = pkt.ip()
		except:
			stat_dropped += 1
			continue

		# drop non-TCP/UDP
		if pkt.p() not in [dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP]:
			stat_dropped += 1
			continue

		# check IP checksum
		if not pkt.ip_ok(True):
			stat_dropped += 1
			continue

		stat_ok += 1
		wr.writepkt(ip, pkt.len, pkt.ts)

	wr.close()

if __name__ == "__main__":
	if len(sys.argv) > 1:
		sys.stderr.write("usage: pcap2ip < src.pcap > dst.pcap\n")
		sys.stderr.write("       supports pipe as input (eg. from bzip2)\n")
		sys.stderr.write("       supports pipe on output (eg. to gzip)\n")
	else:
		main()

