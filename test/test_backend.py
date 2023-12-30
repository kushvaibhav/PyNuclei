#!/usr/bin/python3

import sys

sys.path.append("../PyNuclei")

import PyNuclei

nucleiScanner = PyNuclei.Nuclei()
# http://honey.scanme.sh is a specially made host by Nuclei team to test the setups
scanResult = nucleiScanner.scan(
    "http://honey.scanme.sh", templates=["cves", "network", "ssl"], rateLimit=150
)
print(scanResult)
