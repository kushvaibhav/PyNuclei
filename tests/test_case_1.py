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
        "dns/caa-fingerprint.yaml",
        "network/detection/openssh-detect.yaml",
        "http/miscellaneous/http-trace.yaml",
        "http/miscellaneous/trace-method.yaml",
        "http/exposures/apis/openapi.yaml",
        "http/exposures/apis/openapi.yaml",
        "http/exposures/logs/badarg-log.yaml",
        "http/exposures/logs/ws-ftp-log.yaml",
        "http/cves/2002/CVE-2002-1131.yaml",
        "http/cves/2004/CVE-2004-0519.yaml",
        "http/cves/2007/CVE-2007-0885.yaml",
        "http/cves/2008/CVE-2008-2398.yaml",
    ],
    rateLimit=150,
    verbose=True,
    metrics=True,
    stopAfter=6
)


print("Scan Results:")
print(scanResults)