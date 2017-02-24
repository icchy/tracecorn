import struct

p32 = lambda x: struct.pack('<I', x)
u32 = lambda x: struct.unpack('<I', x)[0]

def pops(uc, ESP):
    esp = uc.mem_read(ESP, 4)
    esp = u32(esp)
    return esp


def string_pack(argv):
    s = ''
    for c in argv:
        if (c == 0):
            break
        s += chr(c)
    return s
