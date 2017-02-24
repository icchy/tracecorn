from lib.windows.pe import *

def test_pe():
    print "kernel32.dll"
    pe = PE("../dll/kernel32.dll")
    print "imagebase: 0x{0:x}".format(pe.imagebase)
    for api in pe.exports:
        print api, hex(pe.exports[api]) 

    print "Downloader.exe"
    pe = PE("../samples/Downloader.exe")
    print "imagebase: 0x{0:x}".format(pe.imagebase)
    for dllname in pe.imports:
        print dllname
        for api in pe.imports[dllname]:
            print api, hex(pe.imports[dllname][api])

    print "AntiDebug.exe"
    pe = PE("../samples/AntiDebug.exe")
    pass


test_pe()
