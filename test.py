import unitracer

uni = unitracer.Win32()
uni.load_code(open('./samples/Wincalc.sc').read())
uni.start(0)
