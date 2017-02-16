import os
import importlib

for d in filter(os.isdir, os.listdir):
    path = os.path.join(d, "{}.dll".format(d))
