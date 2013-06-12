import dpkt
from FlowTuple import *
import dns

class Pkt:
	# decode functions
	_df = {
		dpkt.pcap.DLT_LOOP:   dpkt.loopback.Loopback,
		dpkt.pcap.DLT_NULL:   dpkt.loopback.Loopback,
		dpkt.pcap.DLT_EN10MB: dpkt.ethernet.Ethernet,
		dpkt.pcap.DLT_RAW:    dpkt.ip.IP,
	}

	def __init__(self, pc, data):
		self.pc  = pc
		self.len = data[0]
		self.raw = data[1]
		self.ts  = data[2]

		self._l = {}
		self.decfun = self._df[pc.datalink()]

	def decode(self):
		try: return self._d
		except: pass

		self._d = self.decfun(self.raw)
		return self._d

	# access to network layers
	def layer(self, dpkt_obj):
		try: return self._l[dpkt_obj]
		except: pass

		pkt = self.decode()
		while type(pkt) != dpkt_obj:
			try: pkt = pkt.data
			except: raise Exception("no layer: " + repr(dpkt_obj))

		self._l[dpkt_obj] = pkt
		return self._l[dpkt_obj]

	def ip(self):  return self.layer(dpkt.ip.IP)
	def tcp(self): return self.layer(dpkt.tcp.TCP)
	def udp(self): return self.layer(dpkt.udp.UDP)

	# check all checksums
	def ip_ok(self, tp=False):
		try: ip = self.ip()
		except: return False

		# IP header checksum
		s = dpkt.in_cksum(ip.pack_hdr() + ip.opts)
		if s != 0: return False

		if not tp: return True
		else:      pass # will compute transport protocol checksum
		
		# do we have all the data?
		if len(str(ip)) != ip.len:
			return True

		# get payload
		try:
			if self.is_tcp(): p = str(self.tcp())
			else:             p = str(self.udp())
		except: return True

		s = dpkt.struct.pack('>4s4sxBH', ip.src, ip.dst, ip.p, len(p))
		s = dpkt.in_cksum(s+p)
		if s != 0: return False

		return True

	# basic information
	def p(self):   return self.ip().p
	def is_tcp(self): return self.p() == dpkt.ip.IP_PROTO_TCP
	def is_udp(self): return self.p() == dpkt.ip.IP_PROTO_UDP

	def src(self): return self.ip().src
	def dst(self): return self.ip().dst

	def sport(self):
		if   self.is_tcp(): return self.tcp().sport
		elif self.is_udp(): return self.udp().sport
		else: raise Exception("packet not TCP nor UDP")

	def dport(self):
		if   self.is_tcp(): return self.tcp().dport
		elif self.is_udp(): return self.udp().dport
		else: raise Exception("packet not TCP nor UDP")
			
	def srca(self):
		try: return self._srca
		except:
			self._srca = dpkt.socket.inet_ntoa(self.src())
			return self._srca

	def dsta(self):
		try: return self._dsta
		except:
			self._dsta = dpkt.socket.inet_ntoa(self.dst())
			return self._dsta

	# flow tuple
	def ft(self):
		try: return self._ft
		except:
			self._ft = FlowTuple(
				self.src(), self.sport(),
				self.dst(), self.dport(),
				self.p())
			return self._ft

	# DNS
	def is_dns(self):
		try:    return self._is_dns
		except: self._is_dns = False

		try:
			if self.is_udp():
				udp = self.udp()
				if udp.dport == 53 or udp.sport == 53:
					self._is_dns = True
		except: pass

		return self._is_dns

	def dns(self):
		try: return self._dns
		except: pass

		try:
			self._dns = dns.parse(self.udp().data)
		except:
			self._dns = dns.parse()

		return self._dns

