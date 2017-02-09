def hook_IsDebuggerPresent(id, esp, uc):
    eip_saved = pops(uc, esp)
    print("0x{0:X}")
