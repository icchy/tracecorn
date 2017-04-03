from unicorn.x86_const import *
import importlib


hooks = None
hooks = set(vars().keys())

def RegCreateKeyA(ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()
    lpSubKey = ut.popstack()
    phkResult = ut.popstack()

    print 'RegCreateKeyA (hKey=0x{0:x}, lpSubkey="{1}", phkResult=0x{2:x})'.format(hKey, ut.getstr(lpSubKey), phkResult)
    ut.emu.mem_write(phkResult, ut.pack(0x12341234))
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)


def RegSetValueExA(ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()
    lpValueName = ut.popstack()
    _ = ut.popstack()
    dwType = ut.popstack()
    lpData = ut.popstack()
    cbData = ut.popstack()

    dwType_s = None
    m = importlib.import_module('.'.join(['unitracer', 'lib', 'windows', 'i386', 'advapi32']))
    for n in dir(m):
        if n.startswith('REG_'):
            if getattr(m, n) == dwType:
                dwType_s = n

    print 'RegSetValueExA (hKey=0x{0:x}, lpValueName="{1}", dwType={2}, lpData="{3}", cbData={4})'.format(hKey, ut.getstr(lpValueName), dwType_s, ut.getstr(lpData), cbData)
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)


def RegCloseKey(ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()

    print 'RegCloseKey (hKey=0x{0:x})'.format(hKey)
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)

hooks = set(vars().keys()).difference(hooks)
hooks = [_x for _x in hooks if not _x.startswith('_')]
