from __future__ import absolute_import

from .lib.util import *

class Unitracer(object):
    def __init__(self, mem_size = 15*1024*1024):
        raise NotImplementedError

    def _hook_code(self, uc, address, size, userdata):
        raise NotImplementedError

    def pack(self, x):
        return {32: p32, 64: p64}[self.bits](x)

    def unpack(self, x):
        return {32: u32, 64: u64}[self.bits](x)

    def getstack(self, esp):
        data = self.emu.mem_read(esp, self.bits/8)
        return self.unpack(data)

    def packstr(self, s):
        return s.split("\x00", 1)[0]

    def emu_init(self):
        raise NotImplementedError

    def start(self, offset):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError
