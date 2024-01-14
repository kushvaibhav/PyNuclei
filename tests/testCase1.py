#!/usr/bin/python3
import sys

# Include the PyNuclei path so that we can use the classes found in it
sys.path.append("../PyNuclei")
import PyNuclei


nuclei_scanner = PyNuclei.Nuclei()
# http://honey.scanme.sh is a specially made host by Nuclei team to test the setups

scan_results = nuclei_scanner.scan(
    "https://example.com/",
    templates=[
        "cves", "cnvd"
        "http/exposures/apis/openapi.yaml",
        "http/exposures/apis/openapi.yaml",
        "http/exposures/logs/badarg-log.yaml",
        "http/exposures/logs/ws-ftp-log.yaml"
    ],
    rateLimit=150,
    verbose=False,
    metrics=True,
)


print("Scan Results:")
print(scan_results)