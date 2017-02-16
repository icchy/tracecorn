from struct import pack, unpack


p32 = lambda x:pack("<I", x)
u32 = lambda x:unpack("<I", x)[0]
p64 = lambda x:pack("<Q", x)
u64 = lambda x:unpack("<Q", x)[0]

__all__ = vars().keys()
