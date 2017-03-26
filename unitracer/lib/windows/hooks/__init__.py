from ..i386 import *

import importlib
import os
import sys

sys.path.append(os.path.dirname(__file__)) 

hooks = None
hooks = set(vars().keys())

# load default hook
from .tool.basehook import *


# load defined hooks
for f in os.listdir(os.path.dirname(__file__)):
    if not f.endswith('.py') or f == '__init__.py':
        continue
    name = f[:-3]
    m = importlib.import_module('.'.join(['unitracer', 'lib', 'windows', 'hooks', name]))
    for n in getattr(m, 'hooks'):
        mn = n # module name
        if n not in vars().keys():
            # check function for Unicode or ANSI Strings
            if mn + 'A' in vars().keys() or mn + 'W' in vars().keys():
                mn += 'A' # force convert to ANSI Strings
            else:
                continue
        globals()[mn].hook = getattr(m, n)


hooks = set(vars().keys()).difference(hooks)
hooks = [_x for _x in hooks if not _x.startswith('_')]
