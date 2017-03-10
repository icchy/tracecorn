from __future__ import absolute_import

from .lib.util import *

class Unitracer(object):
    regmap = {
        'ax': [UC_X86_REG_EAX, UC_X86_REG_RAX],
        'bx': [UC_X86_REG_EBX, UC_X86_REG_RBX],
        'cx': [UC_X86_REG_ECX, UC_X86_REG_RCX],
        'dx': [UC_X86_REG_EDX, UC_X86_REG_RDX],
        'di': [UC_X86_REG_EDI, UC_X86_REG_RDI],
        'si': [UC_X86_REG_ESI, UC_X86_REG_RSI],
        'bp': [UC_X86_REG_EBP, UC_X86_REG_RBP],
        'sp': [UC_X86_REG_ESP, UC_X86_REG_RSP],
        'ip': [UC_X86_REG_EIP, UC_X86_REG_RIP],
    }

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

    def popstack(self):
        esp = self.emu.reg_read(self.regmap['sp'][self.bits/64])
        data = self.getstack(esp)
        self.emu.reg_write(self.regmap['sp'][self.bits/64], esp+4)
        return data

    def pushstack(self, data):
        esp = self.emu.reg_read(self.regmap['sp'][self.bits/64])
        self.emu.reg_write(self.regmap['sp'][self.bits/64], esp-4)
        self.emu.mem_write(esp-4, self.pack(data))

    def packstr(self, s):
        return s.split("\x00", 1)[0]

    def getstr(self, addr, size=100):
        data = self.emu.mem_read(addr, size)
        return self.packstr(data)

    def setSP(self, val):
        self.emu.reg_write(self.regmap['sp'][self.bits/64], val)

    def dumpregs(self, regs):
        for reg in regs:
            uc_reg = self.regmap[reg[1:]][self.bits/64]
            val = self.emu.reg_read(uc_reg)
            print(("{0}: 0x{1:0"+str(self.bits/4)+"x}").format(reg, val))

    def emu_init(self):
        raise NotImplementedError

    def start(self, offset):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError
