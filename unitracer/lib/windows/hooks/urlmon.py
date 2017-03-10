from unicorn.x86_const import *

def URLDownloadToFileA(ip, sp, ut):
    emu = ut.emu
    retaddr = ut.popstack()
    pCaller = ut.popstack()
    szURL = ut.popstack()
    szFileName = ut.popstack()
    dwReserved = ut.popstack()
    lpfnCB = ut.popstack()

    print '0x{0:08x}: URLDownloadToFileA ("{1}", "{2}")'.format(ip, ut.getstr(szURL), ut.getstr(szFileName))
    emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)
