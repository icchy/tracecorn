import unitracer
from unitracer.lib.windows.pe import PE

from capstone import *
from capstone.x86_const import *


def test_pe():
    # print "kernel32.dll"
    # pe = PE("./dll/kernel32.dll")
    # print "imagebase: 0x{0:x}".format(pe.imagebase)
    # api = "AcquireSRWLockExclusive"
    # addr = pe.exports[api]
    # print api, hex(addr), addr==0xca06b

    # print "Downloader.exe"
    # pe = PE("./samples/Downloader.exe")
    # for dllname in pe.imports:
    #     print dllname
    #     for api, addr in pe.imports[dllname].items():
    #         print api, hex(addr)

    # print ""
    # pe = PE("./samples/test.exe")
    # for dllname in pe.imports:
    #     print dllname
    #     for api, addr in pe.imports[dllname].items():
    #         print api, hex(addr)
    #     print ""


    print ""
    pe = PE("./dll/kernel32.dll")

    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    data = pe.mapped_data
    for api, addr in pe.exports.items():
        if api == "GetProcessTimes":
            print api
            args = []
            for insn in cs.disasm(data[addr:addr+0x10000], addr):
                print('0x{0:08x}: \t{1}\t{2}'.format(insn.address, insn.mnemonic, insn.op_str))
                for i in insn.operands:
                    if i.value.mem.base != 0 and insn.reg_name(i.value.mem.base) == 'ebp':
                        if i.value.mem.disp not in args and i.value.mem.disp > 0:
                            args.append(i.value.mem.disp)
                if 'ret' in insn.mnemonic:
                    break
            print map(hex, args)
    for dllname in pe.imports:
        for api, addr in pe.imports[dllname].items():
            if api == 'GetProcessTimes':
                print api, hex(addr)


def test_uni():
    uni = unitracer.Windows()
    # uni.load_code(open('./samples/Wincalc.sc').read())
    uni.load_pe('./samples/Downloader.exe')
    uni.start(0)

# test_pe() 
test_uni()
