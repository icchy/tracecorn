from unicorn.x86_const import *


hooks = None
hooks = set(vars().keys())

def URLDownloadToFileA(ut):
    retaddr = ut.popstack()
    pCaller = ut.popstack()
    szURL = ut.popstack()
    szURL_s = ut.getstr(szURL)
    szFileName = ut.popstack()
    szFileName_s = ut.getstr(szFileName)
    dwReserved = ut.popstack()
    lpfnCB = ut.popstack()

    print 'URLDownloadToFileA (pCaller=0x{0:x}, szURL="{1}", szFileName="{2}", lpfnCB=0x{3:x})'.format(pCaller, szURL_s, szFileName_s, lpfnCB)
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)

hooks = set(vars().keys()).difference(hooks)
