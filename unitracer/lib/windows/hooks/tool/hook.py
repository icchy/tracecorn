class Hook(object):
    def __init__(self, name, restype, argtypes):
        self.name = name
        self.restype = restype
        self.argtypes = argtypes

    def hook(self, ut):
        args = []
        retaddr = ut.getstack(0)
        idx = 1
        for t, n in self.argtypes:
            val = ut.getstack(idx)
            if t in []:
                if val == 0:
                    args.append("0x{0:08x}".format(val))
                else:
                    args.append('"{}"'.format(ut.getstr(val)))
            else:
                args.append("0x{0:08x}".format(val))
            idx += 1
        print("Unhooked function: {} ({})".format(self.name, ', '.join(args)))
