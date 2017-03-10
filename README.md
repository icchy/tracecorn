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

from unicorn import x86_const

uni = unitracer.Windows()

# add dll path
uni.dll_path.insert(0, "dlls") # search priority is greater than default

# change stack
uni.STACK_BASE = 0x60000000
uni.STACK_SIZE = 0x10000

# load binary
uni.load_pe('./samples/AntiDebug.exe')
# uni.load_code(open('./samples/URLDownloadToFile.sc').read())

# add hooks
def IsDebuggerPresent(ip, sp, ut):
  emu = ut.emu
  eip_saved = ut.getstack(sp)
  print "IsDebuggerPresent"
  emu.reg_write(UC_X86_REG_EAX, 0)
  emu.mem_write(esp, ut.pack(eip_saved))

uni.hooks['IsDebuggerPresent'] = IsDebuggerPresent

uni.start(0)
```

## Sample
 * running `samples/URLDownloadToFile.sc`
 ![sample](http://imgur.com/AHzR1ZJ)

## TODO
 * 64 bit
 * etc...
