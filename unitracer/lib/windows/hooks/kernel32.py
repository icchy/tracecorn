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


def GetProcAddress(ip, sp, ut):
    retaddr = ut.popstack()
    hModule = ut.popstack()
    lpProcName = ut.popstack()
    lpProcName_s = str(ut.getstr(lpProcName))

    res = None
    if lpProcName_s in ut.dll_funcs.keys():
        res = ut.dll_funcs[lpProcName_s]
    else:
        res = 0x0

    print '0x{0:08x}: GetProcAddress (hModule=0x{1:x}, lpProcName="{2}") = 0x{3:08x}'.format(ip, hModule, lpProcName_s, res)
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def LoadLibraryA(ip, sp, ut):
    retaddr = ut.popstack()
    lpFileName = ut.popstack()
    lpFileName_s = str(ut.getstr(lpFileName))

    res = None
    if lpFileName_s in map(lambda x:x[0], ut.dlls):
        res = filter(lambda x:x[0]==lpFileName_s, ut.dlls)[0][1]
    else:
        res = ut.load_dll(lpFileName_s)

    print '0x{0:08x}: LoadLibraryA (lpFileName="{1}")'.format(ip, lpFileName_s)
    ut.pushstack(retaddr)


def WinExec(ip, sp, ut):
    retaddr = ut.popstack()
    lpCmdLine = ut.popstack()
    lpCmdLine_s = ut.getstr(lpCmdLine)
    uCmdShow = ut.popstack()

    print '0x{0:08x}: WinExec (lpCmdLine="{1}", uCmdShow=0x{2:x})'.format(ip, lpCmdLine_s, uCmdShow)
    ut.emu.reg_write(UC_X86_REG_EAX, 0x20)
    ut.pushstack(retaddr)
