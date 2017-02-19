from lib.windows.pe import *

def test_pe():
    print "kernel32.dll"
    pe = PE("../dll/kernel32.dll")
    print "Downloader.exe"
    pe = PE("../samples/Downloader.exe")
    print "AntiDebug.exe"
    pe = PE("../samples/AntiDebug.exe")
    pass


test_pe()
