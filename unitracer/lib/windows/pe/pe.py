from __future__ import *

from ctypes import *
from io import BytesIO
from struct import pack, unpack

from .defines import *


class PE(object):
    def __init__(self, fname):
        fp = open(fname, "rb")
        buf = BytesIO(fp.read())

        self.fname = fname
        self.fp = fp
        self.buf = buf



    def check(self):
        fp = self.fp

        fp.seek(0)

