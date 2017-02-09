import unitracer

uni = unitracer.Unitracer()
uni.load_code(open('./samples/Wincalc.sc').read())
uni.start(0)
