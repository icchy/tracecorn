from ctypes import *
from win32.defines import *

class IMAGE_DOS_HEADER(Structure):
    _field_ = [
        ("e_magic",         WORD),
        ("e_cblp",          WORD),
    ]
