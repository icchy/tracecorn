import unitracer
from unitracer.lib.windows.pe import PE


def test_pe():
    print "kernel32.dll"
    pe = PE("./dll/kernel32.dll")
    print "imagebase: 0x{0:x}".format(pe.imagebase)
    api = "AcquireSRWLockExclusive"
    addr = pe.exports[api]
    print api, hex(addr), addr==0xca06b

    print "ntdll.dll"
    pe = PE("./dll/ntdll.dll")
    print "imagebase: 0x{0:x}".format(pe.imagebase)

    print "Downloader.exe"
    pe = PE("./samples/Downloader.exe")
    for dllname in pe.imports:
        print dllname
        for api, addr in pe.imports[dllname].items():
            print api, hex(addr)

    print "AntiDebug.exe"
    pe = PE("./samples/AntiDebug.exe")


def test_uni():
    uni = unitracer.Win32()
    uni.load_code(open('./samples/Wincalc.sc').read())
    uni.start(0)

test_pe() 
test_uni()
