import struct
from io import BytesIO


p8  = lambda x:struct.pack("<B", x)
u8  = lambda x:struct.unpack("<B", x)[0]
p16 = lambda x:struct.pack("<H", x)
u16 = lambda x:struct.unpack("<H", x)[0]
p32 = lambda x:struct.pack("<I", x)
u32 = lambda x:struct.unpack("<I", x)[0]
p64 = lambda x:struct.pack("<Q", x)
u64 = lambda x:struct.unpack("<Q", x)[0]


def align(addr, alignment=0x1000):
    mask = ((1<<64)-1) & -alignment
    return (addr + (alignment-1)) & mask


def struct2str(s):
    return BytesIO(s).read()
