#!/usr/bin/env python3
import sys
from urllib.request import urlretrieve

class DownloadFile():

    def __init__(self, source, dest, verbose=False):
        self.source = source
        self.dest = dest
        self.verbose = verbose

        self.download()

    def reporthook(self, blocknum, blocksize, totalsize):
        readsofar = blocknum * blocksize
        if totalsize > 0:
            percent = readsofar * 1e2 / totalsize
            s = "\r%5.1f%% %*d / %d" % (
                percent, len(str(totalsize)), readsofar, totalsize)
            sys.stderr.write(s)
            if readsofar >= totalsize: # near the end
                sys.stderr.write("\n")
        else: # total size is unknown
            sys.stderr.write("read %d\n" % (readsofar,))

    def download(self):
        urlretrieve(self.source, self.dest, self.reporthook)



if __name__ == "__main__":
    d = DownloadFile("https://cert.rlp.de", "cert.rlp.html")
