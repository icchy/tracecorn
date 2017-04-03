def isstr(t):
    pass

class Hook(object):
    def __init__(self, name, restype, argtypes):
        self.name = name
        self.restype = restype
        self.argtypes = argtypes

    def basehook(self, ut):
        args = []
        retaddr = ut.getstack(0)
        idx = 1
        for t, n in self.argtypes:
            v = ut.getstack(idx)
            print t, n
            if n is '':
                n = 'arg{}'.format(idx)
            val = ("0x{0:0"+str(ut.bytes*2)+"x}").format(v)
            if v and t in ["LPCSTR"]:
                val = '{}'.format(repr(str(ut.getstr(v))))
            args.append("{0}={1}".format(n, val))
            idx += 1
        print("Unhooked function: {} ({})".format(self.name, ', '.join(args)))

    def hook(self, ut):
        return self.basehook(ut)
