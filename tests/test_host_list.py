#!/usr/bin/python3
import os
import sys

# Include the PyNuclei path so that we can use the classes found in it
sys.path.append("../PyNuclei")
import PyNuclei

NUCLEI_PATH = f"{os.getcwd()}/bin"
nucleiScanner = PyNuclei.Nuclei(NUCLEI_PATH)

hostsToScan = ["http://honey.scanme.sh", "http://example.com", "http://example.org"]

# http://honey.scanme.sh is a specially made host by Nuclei team to test the setups
scanResults = nucleiScanner.scan(
    hostsToScan,
    templates=[
        "dns",
        "ssl",
        "http/miscellaneous/http-trace.yaml",
    ],
    rateLimit=150,
    verbose=False,
    metrics=True
)

print("Scan Results:")
print(scanResults)