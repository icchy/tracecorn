from unicorn.x86_const import *


hooks = None
hooks = set(vars().keys())

def GetWindowsDirectoryA(ut):
    emu = ut.emu
    retaddr = ut.popstack()
    lpBuffer = ut.popstack()
    uSize = ut.popstack()
    windir = "C:\\Windows"
    print 'GetWindowsDirectoryA = "{0}"'.format(windir)
    emu.mem_write(lpBuffer, windir)
    emu.reg_write(UC_X86_REG_EAX, len(windir))
    ut.pushstack(retaddr)


def lstrcat(ut):
    emu = ut.emu
    retaddr = ut.popstack()
    lpString1 = ut.popstack()
    lpString2 = ut.popstack()
    lpString1_s = ut.getstr(lpString1)
    lpString2_s = ut.getstr(lpString2)

    print 'lstrcat ("{0}", "{1}")'.format(lpString1_s, lpString2_s)
    emu.mem_write(lpString1+len(lpString1_s), str(lpString2_s))
    ut.pushstack(retaddr)


def ExitProcess(ut):
    retaddr = ut.popstack()
    uExitCode = ut.popstack()

    print 'ExitProcess ({0})'.format(uExitCode)
    ut.pushstack(retaddr)


def IsDebuggerPresent(ut):
    retaddr = ut.popstack()
    res = 0

    print 'IsDebuggerPresent = {0}'.format(res)
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GetProcAddress(ut):
    retaddr = ut.popstack()
    hModule = ut.popstack()
    lpProcName = ut.popstack()
    lpProcName_s = str(ut.getstr(lpProcName))

    res = None
    if lpProcName_s in ut.dll_funcs.keys():
        res = ut.dll_funcs[lpProcName_s]
    else:
        res = 0x0

    print 'GetProcAddress (hModule=0x{0:x}, lpProcName="{1}") = 0x{2:08x}'.format(hModule, lpProcName_s, res)
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def LoadLibraryA(ut):
    retaddr = ut.popstack()
    lpFileName = ut.popstack()
    lpFileName_s = str(ut.getstr(lpFileName))

    res = None
    if lpFileName_s in map(lambda x:x[0], ut.dlls):
        res = filter(lambda x:x[0]==lpFileName_s, ut.dlls)[0][1]
    else:
        res = ut.load_dll(lpFileName_s)

    print 'LoadLibraryA (lpFileName="{0}")'.format(lpFileName_s)
    ut.pushstack(retaddr)


def WinExec(ut):
    retaddr = ut.popstack()
    lpCmdLine = ut.popstack()
    lpCmdLine_s = ut.getstr(lpCmdLine)
    uCmdShow = ut.popstack()

    print 'WinExec (lpCmdLine="{0}", uCmdShow=0x{1:x})'.format(lpCmdLine_s, uCmdShow)
    ut.emu.reg_write(UC_X86_REG_EAX, 0x20)
    ut.pushstack(retaddr)

hooks = set(vars().keys()).difference(hooks)
