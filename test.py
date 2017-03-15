import unitracer


def test_uni():
    uni = unitracer.Windows()
    uni.load_code(open('./samples/URLDownloadToFile.sc').read())
    # uni.load_pe('./samples/AntiDebug.exe')
    uni.verbose = False
    uni.start(0)

test_uni()
