import dpkt

class FlowTuple:
	def __init__(self, src, sport, dst, dport, p):
		self.src = src
		self.sport = sport
		self.dst = dst
		self.dport = dport
		self.p = p

		self.hash = hash((src, sport, dst, dport, p))

	def __hash__(self):
		return self.hash

	def __eq__(self, other):
		return (self.hash == other.hash)
			
	def __str__(self):
		try: return self._str
		except: pass

		src = dpkt.socket.inet_ntoa(self.src)
		dst = dpkt.socket.inet_ntoa(self.dst)
		
		if self.p == dpkt.ip.IP_PROTO_TCP:
			p = "TCP"
		else:
			p = "UDP"
		
		self._str = "%s %15s:%-5d -> %15s:%-5d" % (
			p, src, self.sport, dst, self.dport)

		return self._str

	def is_forward(self):
		try: return self._isf
		except: pass
		
		self._isf = (
			(self.src <  self.dst) or
			(self.src == self.dst  and self.sport <= self.dport))
		return self._isf

	def backward(self):
		try: return self._b
		except:
			self._b = FlowTuple(
				self.dst, self.dport,
				self.src, self.sport,
				self.p)
			return self._b

