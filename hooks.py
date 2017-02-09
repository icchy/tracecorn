def pops(uc, ESP):
    esp = uc.mem_read(ESP, 4)
    esp = upck32(esp)
    return esp


def string_pack(argv):
    s = ''
    for c in argv:
        if (c == 0):
            break
        s += chr(c)
    return s


def hook_IsDebuggerPresent(id, esp, uc):
    eip_saved = pops(uc, esp)
    print('0x%0.2x:\tCall IsDebuggerPresent')
    uc.reg_write(UC_X86_REG_EAX, 0)
    uc.mem_write(esp, pck32(eip_saved))


def hook_Sleep(id, esp, uc):
    eip_saved = pops(uc, esp)
    dwMilliseconds = pops(uc, esp + 4)
    print("0x%0.2x:\tCall Sleep (%x)" % (eip_saved, dwMilliseconds))

    uc.mem_write(esp + 4, pck32(eip_saved))


def hook_CloseHandle(id, esp, uc):
    eip_saved = pops(uc, esp)
    handle = pops(uc, esp + 4)
    print("0x%0.2x:\tCall CloseHandle (0x%x)" %(eip_saved,handle))
    global CK
    '''if (CK == 1):
        uc.emu_stop()
    CK += 1'''
    uc.mem_write(esp + 4, pck32(eip_saved))


def hook_SetFilePointer(id, esp, uc):
    eip_saved = pops(uc, esp)
    hFile = pops(uc, esp + 4)
    plDistanceToMove = pops(uc, esp + 8)
    plpDistanceToMoveHigh = pops(uc, esp + 0xc)
    dwMoveMethod = pops(uc, esp + 0x10)
    print(
        "0x%0.2x:\tCall SetFilePointer (hFile = 0x%x, lDistanceToMove = 0x%x, lpDistanceToMoveHigh = 0x%x, dwMoveMethod = 0x%x)" % (eip_saved,
        hFile, plDistanceToMove, plpDistanceToMoveHigh, dwMoveMethod))
    uc.mem_write(esp + 0x10, pck32(eip_saved))


def hook_GetAsyncKeyState(id, esp, uc):
    eip_saved = pops(uc, esp)
    vKey = pops(uc, esp + 4)
    print("0x%0.2x:\tCall GetAsyncKeyState (vKey = 0x%x)" % (eip_saved, vKey))
    uc.reg_write(UC_X86_REG_EAX, 0x1)
    uc.mem_write(esp + 4, pck32(eip_saved))


def hook_GetKeyNameTextA(id, esp, uc):
    eip_saved = pops(uc, esp)
    lParam = pops(uc, esp +4)
    lpString = pops(uc, esp + 8)
    cchSize = pops(uc, esp + 0xc)
    print("0x%0.2x:\tCall GetKeyNameTextA (lParam = 0x%x, lpString = 0x%x, cchSize = 0x%x)" %(eip_saved, lParam, lpString, cchSize))
    uc.reg_write(UC_X86_REG_EAX, 0x1)
    uc.mem_write(esp + 0xc, pck32(eip_saved))


def hook_MapVirtualKeyA(id, esp, uc):
    eip_saved = pops(uc, esp)
    uCode = pops(uc, esp + 4)
    uMapType = pops(uc, esp + 8)
    print("0x%0.2x:\tCall MapVirtualKeyA (uCode = 0x%x, uMapType = 0x%x)" %(eip_saved,uCode, uMapType))
    uc.reg_write(UC_X86_REG_EAX, 0x0)
    uc.mem_write(esp +8, pck32(eip_saved))


def hook_lstrlenA(id, esp, uc):
    eip_saved = pops(uc, esp)
    plpString = pops(uc, esp + 4)
    lpString = uc.mem_read(plpString, 0x100)
    print("0x%0.2x:\tCall lstrlenA (lpString = %s)" %(eip_saved, string_pack(lpString)))
    uc.reg_write(UC_X86_REG_EAX, len(string_pack(lpString)))
    uc.reg_write(esp + 4, eip_saved)


def hook_GetTempPathA(id, esp, uc):
    lBuffer = pops(uc, esp + 4)
    pBuffer = pops(uc, esp + 8)
    eip_saved = pops(uc, esp)
    tempPath = '\\temp\\'
    uc.mem_write(pBuffer, tempPath)
    uc.reg_write(UC_X86_REG_ESP, esp + 0x08)
    uc.reg_write(UC_X86_REG_EAX, len(tempPath))
    print('0x%0.2x:\tCall GetTempPathA\t(len=0x%0.2x, buf=0x%0.2x)' % (eip_saved, lBuffer, pBuffer))
    uc.mem_write(esp + 0x08, pck32(eip_saved))


def hook_CreateFileA(id, esp, uc):
    CreationDisposition = {1: 'CREATE_AWAYS', 2: 'CREATE_NEW', 3: 'OPEN_EXISTING', 4: 'OPEN_ALWAYS',
                           5: 'TRUNCATE_EXISTING'}
    eip_saved = pops(uc, esp)
    lpFileName = pops(uc, esp + 4)
    dwCreationDisposition = pops(uc, esp + 0x14)
    szFileName = uc.mem_read(lpFileName, 0x100)
    FileName = string_pack(szFileName)
    print('0x%0.2x:\tCall CreateFileA (filename=%s,creationDisposition=%s)' % (
        eip_saved, FileName, CreationDisposition[dwCreationDisposition]))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x1c)
    uc.reg_write(UC_X86_REG_EAX, 0x69)
    eip_packed = struct.pack('<I', eip_saved)
    uc.mem_write(esp + 0x1c, eip_packed)


def hook_LoadLibraryA(id, esp, uc):
    pLib = pops(uc, esp + 4)
    eip_saved = pops(uc, esp)
    LIB = uc.mem_read(pLib, 0x100)
    lib = string_pack(LIB)
    print('0x%0.2x:\tCall LoadLibraryA (\'%s\')' % (eip_saved, lib))
    if (lib == 'kernel32.dll'):
        uc.reg_write(UC_X86_REG_EAX, kernel32_base)
    elif (lib == 'urlmon.dll'):
        uc.reg_write(UC_X86_REG_EAX, urlmon_base)
    elif (lib == 'advapi32.dll'):
        uc.reg_write(UC_X86_REG_EAX, DLL_BASE)
    else:
        baseLB = 0x900000
        LB = dll_loader(lib, baseLB)
        uc.mem_write(baseLB, LB)
    uc.reg_write(UC_X86_REG_ESP, esp + 4)
    uc.mem_write(esp + 4, pck32(eip_saved))


def hook_WinExec(id, esp, uc):
    pCmd = pops(uc, esp + 4)
    nshow = pops(uc, esp + 8)
    eip_saved = pops(uc, esp)
    CMD = uc.mem_read(pCmd, 0x100)
    cmd = string_pack(CMD)
    uc.reg_write(UC_X86_REG_ESP, esp + 0x08)
    print('0x%0.2x:\tCall WinExec (\'%s\', %d)' % (eip_saved, cmd, nshow))
    uc.mem_write(esp + 0x08, pck32(eip_saved))


def hook_WriteFile(id, esp, uc):
    eip_saved = pops(uc, esp)
    hFile = pops(uc, esp + 4)
    lpBuff = pops(uc, esp + 8)
    nNumberOfBytesWrite = pops(uc, esp + 0x0c)
    lpNumberOfBytesWritten = pops(uc, esp + 0x10)
    print('0x%0.2x:\tCall WriteFile (hFile=0x%0.2x, lpBuff=0x%0.2x, nNumberOfBytesWrite=0x%0.2x)' % (eip_saved,hFile,lpBuff,nNumberOfBytesWrite))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x14)
    uc.mem_write(esp + 0x14, pck32(eip_saved))
    uc.mem_write(lpNumberOfBytesWritten, struct.pack('<I', nNumberOfBytesWrite))


def hook_ReadFile(id, esp, uc):
    eip_saved = pops(uc, esp)
    hFile = pops(uc, esp + 4)
    lpBuff = pops(uc, esp + 8)
    nNumberOfBytesToRead = pops(uc, esp + 0x0c)
    lpNumberOfBytesRead = pops(uc, esp + 0x10)
    print('0x%0.2x:\tCall ReadFile With (hFile=0x%0.2x,lpBuff=0x%0.2x,nNumberOfBytesToRead=0x%0.2x)' % (
        hFile, lpBuff, nNumberOfBytesToRead))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x14)
    uc.reg_write(UC_X86_REG_EAX, 0x69)
    uc.mem_write(lpNumberOfBytesRead, struct.pack('<I', nNumberOfBytesToRead))
    uc.mem_write(esp + 0x14, pck32(eip_saved))


def hook_URLDownloadToFileA(id, esp, uc):
    eip_saved = pops(uc, esp)
    pUrl = pops(uc, esp + 8)
    pFileName = pops(uc, esp + 0x0c)
    szUrl = uc.mem_read(pUrl, 0x100)
    szFileName = uc.mem_read(pFileName, 0x100)
    Url = string_pack(szUrl)
    FileName = string_pack(szFileName)
    print('0x%0.2x:\tCall URLDownloadToFileA (Url=%s, LocalPath=%s)\n' % (eip_saved, Url, FileName))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x14)
    uc.mem_write(esp + 0x14, pck32(eip_saved))


def hook_ExitProcess(eip, esp, uc):
    eip_saved = pops(uc, esp)
    uExitcode = pops(uc, esp + 4)
    print('0x%0.2x:\tCall ExitProcess (0x%0.2x)' % (eip_saved, uExitcode))
    uc.emu_stop()


def hook_GetWindowsDirectoryA(id, esp, uc):
    eip_saved = pops(uc, esp)
    buf = pops(uc, esp + 0x4)
    uSize = pops(uc, esp + 0x8)
    print("0x%x:\tCall GetWindowsDirectoryA (buf = 0x%x)" % (eip_saved, buf))
    uc.mem_write(buf, struct.pack('10s', "C:\Windows"))
    uc.reg_write(UC_X86_REG_EAX, 0xa)
    uc.reg_write(UC_X86_REG_ESP, esp + 8)
    uc.mem_write(esp + 0x8, pck32(eip_saved))


def hook_lstrcatA(eip, esp, uc):
    eip_saved = pops(uc, esp)
    plString1 = pops(uc, esp + 0x4)
    arg1 = uc.mem_read(plString1, 0x100)
    plString2 = pops(uc, esp + 0x8)
    arg2 = uc.mem_read(plString2, 0x100)
    lString1 = string_pack(arg1)
    lString2 = string_pack(arg2)
    print("0x%x:\tCall lstrcatA (String2: \'%s\', String1: \'%s\')" % (eip_saved, lString2, lString1))
    lString1 += lString2
    uc.mem_write(plString1, lString1)
    uc.reg_write(UC_X86_REG_ESP, esp + 0x8)
    uc.mem_write(esp + 0x8, pck32(eip_saved))


def hook_RegCreateKeyA(eip, esp, uc):
    hkey = {2147483648: 'HKEY_CLASSES_ROOT', 2147483649: 'HKEY_CURRENT_USER', 2147483650: 'HKEY_LOCAL_MACHINE',
            2147483651: 'HKEY_USERS', 2147483652: 'HKEY_PERFORMANCE_DATA', 2147483653: 'HKEY_CURRENT_CONFIG',
            2147483654: 'HKEY_DYN_DATA'}
    eip_saved = pops(uc, esp)
    hKey = pops(uc, esp + 4)
    lpSubKey = pops(uc, esp + 8)
    phkResult = pops(uc, esp + 0xc)
    SubKey = uc.mem_read(lpSubKey, 0x100)
    subkey = string_pack(SubKey)
    print("0x%x:\tCall RegCreateKeyA function With key: %s\%s\n" % (eip_saved, hkey[hKey], subkey))
    uc.mem_write(phkResult, pck32(0x69))
    uc.reg_write(UC_X86_REG_EAX, 0)
    uc.reg_write(UC_X86_REG_ESP, esp + 0xc)
    uc.mem_write(esp + 0xc, pck32(eip_saved))


def hook_RegCloseKey(eip, esp, uc):
    eip_saved = pops(uc, esp)
    hKey = pops(uc, esp +4)
    print("0x%x:\tCall RegCloseKey function (hKey= 0x%x)" % (eip_saved, hKey))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x4)
    uc.mem_write(esp + 0x4, pck32(eip_saved))


def hook_RegSetValueExA(eip, esp, uc):
    eip_saved = pops(uc, esp)
    hKey = pops(uc, esp + 0x4)
    lpValueName = pops(uc, esp + 0x8)
    Reserved = pops(uc, esp + 0xc)
    dwType = pops(uc, esp + 0x10)
    lpData = pops(uc, esp + 0x14)
    cbData = pops(uc, esp + 0x18)
    ValueName = uc.mem_read(lpValueName, 0x100)
    Data = uc.mem_read(lpData, 0x100)
    print("0x%x:\tCall RegSetValueExA (hKey = 0x%x, ValueName: %s, Registry data: %s)\n" % (
        eip_saved, hKey, string_pack(ValueName), string_pack(Data)))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x18)
    uc.mem_write(esp + 0x18, pck32(eip_saved))


def hook_GetProcAddress(id, esp, uc):
    eip_saved = pops(uc, esp)
    hModule = pops(uc, esp + 4)
    lpProcName = pops(uc, esp + 8)
    procName = string_pack(uc.mem_read(lpProcName, 0x100))
    print("0x%x: \tCall GetProcAddress (Hmodule = %x, ProcName = %s)" % (eip_saved, hModule, procName))
    for e in imp_dll:
        if imp_dll[e] == procName:
            uc.reg_write(UC_X86_REG_EAX, e)
            break
    uc.reg_write(UC_X86_REG_ESP, esp + 0x8)
    uc.mem_write(esp + 0x8, pck32(eip_saved))

