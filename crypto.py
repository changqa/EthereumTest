import hashlib
import sha3
import struct

## Ethereum uses the keccak-256 hash algorithm
def keccak256(s):
    k = sha3.keccak_256()
    k.update(s)
    return k.digest()

class PackTest(object):
	v = b'\x01'
	def __init__(self, st, i):
		self.st = st
		self.i = i

	def pack(self):
		return [self.v, struct.pack(">I", self.i)]