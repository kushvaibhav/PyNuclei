#!/usr/bin/python3

import sys
import time
from threading import Thread

# Include the PyNuclei path so that we can use the classes found in it
sys.path.append("../PyNuclei")
import PyNuclei


def monitoring_thread(nuclei_scanner):
    """Check the nuclei_scanner variables values and print"""

    # Wait for the running to go above 0
    cold_start = False
    while True:
        print(
            f"{nuclei_scanner.running=} {nuclei_scanner.done=} "
            f"{nuclei_scanner.current_progress}/{nuclei_scanner.max_progress}"
            f"\n{nuclei_scanner.eta=}"
        )

        if nuclei_scanner.running > 0:
            cold_start = True

        if (
            nuclei_scanner.running == 0
            and nuclei_scanner.done == nuclei_scanner.selected_templates_count
        ):
            if cold_start:
                # Wait for it to warm up
                break

        time.sleep(1)


nuclei_scanner = PyNuclei.Nuclei()
# http://honey.scanme.sh is a specially made host by Nuclei team to test the setups

t = Thread(target=monitoring_thread, args=[nuclei_scanner])
t.start()
scan_results = nuclei_scanner.scan(
    "https://example.com/",
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
    rate_limit=150,
    verbose=True,
    metrics=True,
)

print(scan_results)
