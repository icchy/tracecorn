import os
import re


funcs = []
re_api = re.compile("^def ([A-Z][a-zA-Z0-9]+)")
script = ""

for f in sorted(filter(
        lambda x:x.endswith(".py") and "__init__" not in x and "amd64" not in x, 
        os.listdir("win32"))):
    path = os.path.join("win32", f)
    script += open(path).read()
    for l in open(path).read().splitlines():
        m = re_api.match(l)
        if m:
            funcs.append([m.group(1)])

for api in funcs:
    name = api[0]
    for l in script.splitlines():
        if "{}.argtypes".format(name) in l:
            if '=' in l:
                api.append(l.split('=')[1].strip())
        if "{}.restype".format(name) in l:
            if '=' in l:
                api.append(l.split('=')[1].strip())

for api in funcs:
    if len(api) == 3:
        name, argtypes, restype = api
        print("{} = Hook({}, {})".format(name, restype, argtypes))

