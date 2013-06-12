from PcapBuf import *

DATA_LEN = 0
DATA_RAW = 1
DATA_TS  = 2

class Cork:
	def __init__(self):
		self.ts = float("inf")

class Pktsrc:
	def __init__(self, name, filt=None, dns=None):
		self.ppkt = None
		self.ppkt2 = None
		self.dnspkt = None

		self.tr = PcapBuf(name, filt)
		if dns:
			self.dns = PcapBuf(dns, "udp and port 53")
		else:
			self.dns = None

	# ensure we have a DNS packet in buffer
	def update_dns(self):
		if not self.dnspkt:
			try:    self.dnspkt = self.dns.next()
			except: self.dnspkt = Cork()

	def __iter__(self):
		return self

	def next(self):
		if self.ppkt:
			pkt, self.ppkt = self.ppkt, None
			return pkt

		# ensure we have a DNS packet to compare
		self.update_dns()

		if self.ppkt2:
			# recall last IP packet
			pkt, self.ppkt2 = self.ppkt2, None
		else:
			# read traffic packet
			pkt = self.tr.next()

		if pkt.ts >= self.dnspkt.ts:
			# we're ahead DNS - let it catch-up
			self.ppkt2 = pkt
			pkt, self.dnspkt = self.dnspkt, None
		else:
			# we're behind DNS - return traffic
			pass

		return pkt

	def peek(self):
		if not self.ppkt:
			try:    self.ppkt = self.next()
			except: return None

		return self.ppkt

