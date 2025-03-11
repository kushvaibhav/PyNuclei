#!/usr/bin/python3
import os
import sys

# Include the PyNuclei path so that we can use the classes found in it
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "PyNuclei")))
import PyNuclei

NUCLEI_PATH = f"{os.getcwd()}/bin"
nucleiScanner = PyNuclei.Nuclei()

# honey.scanme.sh is a specially made host by Nuclei team to test the setups
scanResults = nucleiScanner.scan(
    "67.205.158.113",
    templates=[
        "javascript",
        "network",
        "dns",
        "ssl",
    ],
    generatePoc=True,
    rateLimit=150,
    verbose=False,
    metrics=True
)

print("Scan Results:")
print(scanResults)