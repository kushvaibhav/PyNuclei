#!/usr/bin/python3
import os
import sys

# Include the PyNuclei path so that we can use the classes found in it
sys.path.append("../PyNuclei")
import PyNuclei

NUCLEI_PATH = f"{os.getcwd()}/bin"
nucleiScanner = PyNuclei.Nuclei(NUCLEI_PATH)

# http://honey.scanme.sh is a specially made host by Nuclei team to test the setups
scanResults = nucleiScanner.scan(
    "http://honey.scanme.sh",
    templates=[
        "cnvd",
        "cves",
        "default-logins",
        "exposed-panels",
        "exposures",
        "file",
        "misconfiguration",
        "miscellaneous",
        "takeovers",
        "technologies",
        "token-spray",
        "vulnerabilities",
        "network",
        "dns",
        "iot",
        "ssl",
    ],
    rateLimit=150,
    verbose=False,
    metrics=True
)

print("Scan Results:")
print(scanResults)