from unicorn.x86_const import *

def URLDownloadToFileA(ip, sp, ut):
    retaddr = ut.popstack()
    pCaller = ut.popstack()
    szURL = ut.popstack()
    szURL_s = ut.getstr(szURL)
    szFileName = ut.popstack()
    szFileName_s = ut.getstr(szFileName)
    dwReserved = ut.popstack()
    lpfnCB = ut.popstack()

    print '0x{0:08x}: URLDownloadToFileA (pCaller=0x{1:x}, szURL="{2}", szFileName="{3}", lpfnCB=0x{4:x})'.format(ip, pCaller, szURL_s, szFileName_s, lpfnCB)
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)
