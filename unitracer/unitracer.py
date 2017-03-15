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

    def getstack(self, idx):
        sp = self.getSP()
        data = self.emu.mem_read(sp+(idx*self.bytes), self.bytes)
        return self.unpack(data)

    def setstack(self, idx, val):
        sp = self.getSP()
        self.emu.mem_write(sp+(idx*self.bytes), self.pack(val))

    def popstack(self):
        sp = self.getSP()
        data = self.getstack(0)
        self.setSP(sp+self.bytes)
        return data

    def pushstack(self, data):
        sp = self.getSP()
        self.setstack(-1, data)
        self.setSP(sp-self.bytes)

    def setSP(self, val):
        self.emu.reg_write(self.ucreg('sp'), val)

    def getSP(self):
        return self.emu.reg_read(self.ucreg('sp'))

    def packstr(self, s):
        return s.split("\x00", 1)[0]

    def getstr(self, addr, size=100):
        data = ""
        for i in range(size):
            data += self.emu.mem_read(addr+i, 1)
            if data.endswith('\x00'):
                break
        return self.packstr(data)

    def ucreg(self, n):
        return self.regmap[n][self.is64]

    def dumpregs(self, regs):
        for reg in regs:
            val = self.emu.reg_read(self.ucreg(reg[1:].lower()))
            print(("{0}: 0x{1:0"+str(self.bytes*2)+"x}").format(reg, val))

    def emu_init(self):
        raise NotImplementedError

    def start(self, offset):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError
