#!/usr/bin/python3

import sys
import time
from threading import Thread
from string import Formatter
import os

# Include the PyNuclei path so that we can use the classes found in it
sys.path.append("../PyNuclei")
import PyNuclei


def strfdelta(tdelta, fmt="{D:02}d {H:02}h {M:02}m {S:02}s", inputtype="timedelta"):
    """Convert a datetime.timedelta object or a regular number to a custom-
    formatted string, just like the stftime() method does for datetime.datetime
    objects.

    The fmt argument allows custom formatting to be specified.  Fields can
    include seconds, minutes, hours, days, and weeks.  Each field is optional.

    Some examples:
        '{D:02}d {H:02}h {M:02}m {S:02}s' --> '05d 08h 04m 02s' (default)
        '{W}w {D}d {H}:{M:02}:{S:02}'     --> '4w 5d 8:04:02'
        '{D:2}d {H:2}:{M:02}:{S:02}'      --> ' 5d  8:04:02'
        '{H}h {S}s'                       --> '72h 800s'

    The inputtype argument allows tdelta to be a regular number instead of the
    default, which is a datetime.timedelta object.  Valid inputtype strings:
        's', 'seconds',
        'm', 'minutes',
        'h', 'hours',
        'd', 'days',
        'w', 'weeks'
    """

    # Convert tdelta to integer seconds.
    if inputtype == "timedelta":
        remainder = int(tdelta.total_seconds())
    elif inputtype in ["s", "seconds"]:
        remainder = int(tdelta)
    elif inputtype in ["m", "minutes"]:
        remainder = int(tdelta) * 60
    elif inputtype in ["h", "hours"]:
        remainder = int(tdelta) * 3600
    elif inputtype in ["d", "days"]:
        remainder = int(tdelta) * 86400
    elif inputtype in ["w", "weeks"]:
        remainder = int(tdelta) * 604800

    f = Formatter()
    desired_fields = [field_tuple[1] for field_tuple in f.parse(fmt)]
    possible_fields = ("W", "D", "H", "M", "S")
    constants = {"W": 604800, "D": 86400, "H": 3600, "M": 60, "S": 1}
    values = {}
    for field in possible_fields:
        if field in desired_fields and field in constants:
            values[field], remainder = divmod(remainder, constants[field])
    return f.format(fmt, **values)


def monitoring_thread(nuclei_scanner):
    """Check the nuclei_scanner variables values and print"""

    # Wait for the running to go above 0
    cold_start = False
    while True:
        if nuclei_scanner.findings > 1:
            nuclei_scanner.stop()

        if nuclei_scanner.max_progress == 0:
            time.sleep(1)
            continue

        print(
            f"{nuclei_scanner.running=} {nuclei_scanner.done=} {nuclei_scanner.findings=} "
            f"{nuclei_scanner.current_progress/nuclei_scanner.max_progress * 100.0:.2f}%"
            f"\nEta: {strfdelta(nuclei_scanner.eta)}"
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


home_folder = os.path.expanduser("~")
nuclei_scanner = PyNuclei.Nuclei(nuclei_path=f"{home_folder}/go/bin")
# http://honey.scanme.sh is a specially made host by Nuclei team to test the setups

t = Thread(target=monitoring_thread, args=[nuclei_scanner])
t.start()
scan_results = nuclei_scanner.scan(
    "https://192.168.8.109/",
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
