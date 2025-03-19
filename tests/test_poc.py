#!/usr/bin/python3

# Include the PyNuclei path so that we can use the classes found in it
# sys.path.append("../PyNuclei")
import PyNuclei

nucleiScanner = PyNuclei.Nuclei()

# http://honey.scanme.sh is a specially made host by Nuclei team to test the setups
scanResults = nucleiScanner.scan(
    "honey.scanme.sh",
    templates=[
        "dns",
        "ssl",
        "misconfiguration",
        "network"
    ],
    rateLimit=150,
    verbose=False,
    metrics=True,
    generatePoc=True
)

print("Scan Results:")
print(scanResults)