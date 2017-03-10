# unitracer
Windows API tracer for malware

 * based on [Dutas](https://github.com/dungtv543/Dutas) and [PyAna](https://github.com/PyAna/PyAna)

## Requirements
 * Unicorn 1.0
 * some dlls

## Features
 * Windows API trace/hook
 * setup special data of TIB, PEB, LDR... (WIP)
 * using [original PE parser](https://github.com/icchy/pe) (faster than pefile)

## Usage
```python
import unitracer

from unicorn import x86_const

uni = unitracer.Windows()

uni.load_pe('./samples/AntiDebug.exe')

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

## TODO
 * complete preparation of LDR\_MODULE 
 * 64 bit
 * etc...
