import struct


p32 = lambda x:struct.pack("<I", x)
u32 = lambda x:struct.unpack("<I", x)[0]
p64 = lambda x:struct.pack("<Q", x)
u64 = lambda x:struct.unpack("<Q", x)[0]

__all__ = vars().keys()
