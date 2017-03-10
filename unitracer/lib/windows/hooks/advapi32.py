from unicorn.x86_const import *
from ..i386 import advapi32

def RegCreateKeyA(ip, sp, ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()
    lpSubKey = ut.popstack()
    phkResult = ut.popstack()

    print '0x{0:08x}: RegCreateKeyA (hKey=0x{1:x}, lpSubkey="{2}", phkResult=0x{3:x})'.format(ip, hKey, ut.getstr(lpSubKey), phkResult)
    ut.emu.mem_write(phkResult, ut.pack(0x12341234))
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)


def RegSetValueExA(ip, sp, ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()
    lpValueName = ut.popstack()
    _ = ut.popstack()
    dwType = ut.popstack()
    lpData = ut.popstack()
    cbData = ut.popstack()

    dwType_s = None
    for n in dir(advapi32):
        if n.startswith('REG_'):
            if getattr(advapi32, n) == dwType:
                dwType_s = n

    print '0x{0:08x}: RegSetValueExA (hKey=0x{1:x}, lpValueName="{2}", dwType={3}, lpData="{4}", cbData={5})'.format(ip, hKey, ut.getstr(lpValueName), dwType_s, ut.getstr(lpData), cbData)
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)


def RegCloseKey(ip, sp, ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()

    print '0x{0:08x}: RegCloseKey (hKey=0x{1:x})'.format(ip, hKey)
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)
