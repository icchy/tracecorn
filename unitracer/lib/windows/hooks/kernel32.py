from unicorn.x86_const import *

def GetWindowsDirectoryA(ip, sp, ut):
    emu = ut.emu
    retaddr = ut.popstack()
    lpBuffer = ut.popstack()
    uSize = ut.popstack()
    windir = "C:\\Windows"
    print '0x{0:08x}: GetWindowsDirectoryA = "{1}"'.format(ip, windir)
    emu.mem_write(lpBuffer, windir)
    emu.reg_write(UC_X86_REG_EAX, len(windir))
    ut.pushstack(retaddr)


def lstrcat(ip, sp, ut):
    emu = ut.emu
    retaddr = ut.popstack()
    lpString1 = ut.popstack()
    lpString2 = ut.popstack()
    lpString1_s = ut.getstr(lpString1)
    lpString2_s = ut.getstr(lpString2)

    print '0x{0:08x}: lstrcat ("{1}", "{2}")'.format(ip, lpString1_s, lpString2_s)
    emu.mem_write(lpString1+len(lpString1_s), str(lpString2_s))
    ut.pushstack(retaddr)


def ExitProcess(ip, sp, ut):
    retaddr = ut.popstack()
    uExitCode = ut.popstack()

    print '0x{0:08x}: ExitProcess ({1})'.format(ip, uExitCode)
    ut.pushstack(retaddr)


def IsDebuggerPresent(ip, sp, ut):
    retaddr = ut.popstack()
    res = 0

    print '0x{0:08x}: IsDebuggerPresent = {1}'.format(ip, res)
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)
