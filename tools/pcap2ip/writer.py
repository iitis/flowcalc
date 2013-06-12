#
# Imported from dpkt
#

import dpkt

def tsplit(ts):
	ts2 = "%.6f" % ts
	return (int(ts2[:-7]), int(ts2[-6:]))

class Writer(object):
	def __init__(self, fileobj, snaplen=1500, linktype=dpkt.pcap.DLT_EN10MB):
		self.__f = fileobj
		fh = dpkt.pcap.FileHdr(snaplen=snaplen, linktype=linktype)
		self.__f.write(str(fh))

	def writepkt(self, pkt, plen, ts):
		s = str(pkt)
		n = len(s)

		sec, usec = tsplit(ts)
		ph = dpkt.pcap.PktHdr(tv_sec=sec, tv_usec=usec, caplen=n, len=plen)

		self.__f.write(str(ph))
		self.__f.write(s)

	def close(self):
		self.__f.close()
