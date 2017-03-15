# unitracer
Windows API tracer for malware

 * based on [Dutas](https://github.com/dungtv543/Dutas) and [PyAna](https://github.com/PyAna/PyAna)

## Requirements
 * Unicorn 1.0
 * Capstone
 * some dlls

## Features
 * Windows API trace/hook
 * setup special data of TIB, PEB, LDR...
 * using [original PE parser](https://github.com/icchy/pe) (faster than pefile)

## Usage
```python
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
def IsDebuggerPresent(ip, sp, ut):
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
```

## Sample
 * running `samples/URLDownloadToFile.sc`
 ![sample](http://imgur.com/AHzR1ZJ.png)

## TODO
 * 64 bit
 * etc...
