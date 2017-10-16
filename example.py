import unitracer
from unicorn.x86_const import *


uni = unitracer.Windows()

# add search path for dll
uni.dll_path.insert(0, "dlls")

# change stack
uni.STACK_BASE = 0x60000000
uni.STACK_SIZE = 0x10000

# load binary
uni.load_pe('./samples/AntiDebug.exe')
# uni.load_code(open('./samples/URLDownloadToFile.sc').read())

# add api hooks
def IsDebuggerPresent(ut):
    emu = ut.emu
    retaddr = ut.popstack()
    print "IsDebuggerPresent"
    emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)

uni.api_hooks['IsDebuggerPresent'] = IsDebuggerPresent

# add original hooks
def myhook(ut, address, size, userdata):
    if address == 0xdeadbeef:
        ut.dumpregs(["eax", "ebx"])

uni.hooks.append(myhook)

# suppress verbose output (disassemble)
uni.verbose = False

uni.start(0)
