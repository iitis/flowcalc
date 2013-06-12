import pcap
from Pkt import *

class PcapBuf:
	def __init__(self, name, filt=None):
		self.pc = pcap.pcapObject()
		self.pc.open_offline(name)
		if filt:
			self.pc.setfilter(filt, True, 0)
		self.buf = []

	def update_buf(self):
		if not self.pc or len(self.buf) > 0:
			return

		self.pc.dispatch(100,
			lambda plen, raw, ts: \
				self.buf.append((plen, raw, ts)))

		if len(self.buf) == 0:
			self.pc = None

	def __iter__(self):
		return self

	def next(self):
		try:
			self.update_buf()
			data = self.buf.pop(0)
		except: raise StopIteration
		return Pkt(self.pc, data)

	def peek(self):
		try:
			self.update_buf()
			data = self.buf[0]
		except: raise StopIteration
		return Pkt(self.pc, data)

