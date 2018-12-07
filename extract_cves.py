#!/usr/bin/env python3

import urllib.request
import datetime
import argparse
import os

__version__ = 0.01
__date__ = "07.12.2018"


class ExtractCVEs():

    def __init__(self, verbose=False):
        self.cves = []
        self.chunks = []
        self.errors = []
        self.exit_code = 0

        self.verbose = verbose

    def _verb(self, msg):
        """ prints messages if verbosity is turned on """

        if self.verbose is True:
            print(msg)

    def get_url(self, url):
        """
        opens a url on a webserver
        and calls helper function to extract the CVEs
        """

        agent = "'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3)\
                AppleWebKit/537.36 (KHTML, like Gecko)\
                Chrome/35.0.1916.47 Safari/537.36'"
        self.url = url

        self._verb("Getting page: {0}".format(self.url))
        try:
            req = urllib.request.Request(url, data=None, headers={'User-Agent':  agent})
            self.response = urllib.request.urlopen(req)
        except Exception as e:
            print("Error getting page: '{0}' / Exit".format(e))
            exit(-1)

        self._chunk_file()
        self._extract_cves()

    def get_file(self, filename):
        """
        opens a local file
        and calls helper functions to extract the CVEs
        """

        self._verb("Getting file: {0}".format(filename))
        self.filename = filename
        try:
            with open(self.filename, "rb") as self.response:
                self._chunk_file()
        except FileNotFoundError:
            print("Err: File not Found / Exit")
            exit(-150)

        self._extract_cves()

    def _chunk_file(self):
        """
        accesses the self.response
        created by get_file() or get_url()
        and creates chunks from this ressource
        """

        for line in self.response:
            line = line.decode()
            line = line.strip()
            # print(line)
            if len(line) == 0:
                continue
            # check if the line contains a CVE
            elif line.find("CVE-") == -1:
                continue

            line = line.replace(".", " ")
            line = line.replace(",", " ")
            line = line.replace(";", " ")
            line = line.split(" ")
            for l in line:
                # check if the chunk contains a CVE
                if l.find("CVE-") > -1:
                    self.chunks.append(l)

    def check_cve(self, cve, verbose=0):
        """
        Checks if a cve seems to be formal valid
        """

        errors = []

        self._verb("Checking CVE: {0}".format(cve))

        #if not len(cve) >= 13:
        #    errors.append("The minimum length of a CVE is thirteen chars")

        if cve.count("-") != 2:
            errors.append("A valid CVE contains two dashes")

        if not cve.startswith("CVE-"):
            errors.append("A valid CVE starts with CVE-")
        
        # very basic tests failed
        if len(errors) > 0:
            return(len(errors), errors)

        cve = cve.split("-")

        if not len(cve) == 3:
            errors.append("A sequenze (CVE-YYYY-SSSS) seems to be missing")

        if not cve[0] == "CVE":
            errors.append("Part one of a valid CVE is 'CVE'")
        
        # TODO: change this 9999 ad
        if not len(cve[1]) == 4 or not cve[1].isdigit():
            errors.append("Part two of a valid CVE contains four digits representing the year")

        if not len(cve[2]) >= 4 or not cve[2].isdigit():
            errors.append("Sequence number is 4 digits minium length")
        
        # basic tests failed
        if len(errors) > 0:
            return(len(errors), errors)

        cve_year = cve[1]
        cve_no = cve[2]
        cve_year = int(cve_year)
        cve_no = int(cve_no)

        if cve_year < 1999:
            errors.append("Their are no CVE numbers before 1999")
                
        if cve_year < 2016 and cve_no > 9999:
            msg = "CVEs before 2016 had a maxium of four digits in their sequence number"
            errors.append(msg)

        if cve_no > 9999999:
            errors.append("CVEs have a maximum of 7 digits in their sequence number")

        now = datetime.datetime.now()
        if cve_year - now.year >= 2:
            msg = "A year {0} is formal correct but uncommon as we have {1}".format(cve_year, now.year)
            errors.append(msg)
    
        if len(errors) == 0:
            return(0, ["OK"])
        else:
            return(len(errors), errors)

    @staticmethod
    def extract_cve(chunk):
            """
            extracts the CVEs from one chunk
            """

            hit = chunk.find("CVE-")
            start = hit+4
            cve = "CVE-"
            i = 0
            len_chunk = len(chunk)-start
            while True:
                i += 1
                # print(i, len_chunk, chunk[start])
                if chunk[start].isdigit():
                    cve = "{0}{1}".format(cve, chunk[start])
                    start = start + 1
                elif chunk[start] == "-":
                    cve = "{0}-".format(cve)
                    start = start + 1
                else:
                    break

                if i == len_chunk:
                    break

            return(cve)

    def _extract_cves(self):
        """
        Iterates over the chunks created by _create_chunks
        and calls extract_cve and check_cve
        """

        for chunk in self.chunks:
            self._verb("Chunk: '{0}'".format(chunk))
            cve = self.extract_cve(chunk)
            status, msg = self.check_cve(cve)
            self._verb("CVE: {0} Status {1} Message {2}".format(cve, status, msg))
            if status == 0:
                self.cves.append(cve)

        self.cves = list(set(self.cves))
        self.cves.sort()

    def get_cves(self):
        return(self.cves)

    def print_cves(self):

        output = "\n"
        for cve in self.cves:
            output = "{0}{1}, ".format(output, cve)

        output = output[0:-2]

        print(output)

    
    def compare_real_cves(self):
        import gzip
        import time

        if len(self.cves) == 0:
            print("No CVEs present")
            exit(0)
   
        fn = "allitems.csv.gz"
        self.existing_cves = []

        if not os.path.exists(fn):
            print("File allitems.csv.gz does not exists")
            print("Please download it at:")
            print("https://cve.mitre.org/data/downloads/allitems.csv.gz")
            exit(-1)

        mtime = int(os.path.getmtime(fn))
        now = int(time.time())

        age = (now - mtime)/3600
        print("Age of CVE database: {0} hours".format(age))

        if age > 48:
            print("Your CVE database seems outdated")
            print("Please download a actual one at:")
            print("https://cve.mitre.org/data/downloads/allitems.csv.gz")

        with gzip.open(fn,'rb') as f:
            for line in f:
                try:
                    line = line.decode()
                except UnicodeDecodeError:
                    print("Error Reading Line")
                    continue
                line = line.split(",")
                self.existing_cves.append((line[0]))
        
        tmp = []
        for cve in self.cves:
            if not cve in self.existing_cves:
                print("This CVE seems not to exist: {0}".format(cve))
            else:
                tmp.append(cve)

        self.cves = tmp

if __name__ == "__main__":


    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group()
    g.add_argument("-u", "--url", help="url to fetch and extract CVEs")
    g.add_argument("-f", "--file", help="path to local file to extract CVEs")
    g.add_argument("-c", "--check", help="check a CVE for formal validity")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    p.add_argument("-e", "--extended", action="store_true", help="checks found cves against the Mitre DB, which has to be downloaded first")
    p.add_argument("-V", "--version", action="store_true", help="print the version and exit")
    args = p.parse_args()

    if args.version:
        print("Version: {0} build {1}".format(__version__, __date__))
        exit(0)

    verbose = args.verbose

    if args.url is None and args.file is None:
        if args.check is None:
            print("Parameter Missing")
            exit(-120)

    c = ExtractCVEs(verbose)

    if args.url:
        c.get_url(args.url)
    elif args.file:
        c.get_file(args.file)
    elif args.check:
        s, m = c.check_cve(args.check, verbose=1)
        print("CVE: {0} Status: {1} Message: {2}".format(args.check, s, m))
        exit(0)

    if args.extended == True:
        c.compare_real_cves()
    c.print_cves()

    # Todo
    exit(0)
