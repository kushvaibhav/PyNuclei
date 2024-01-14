# PyNuclei

PyNuclei is an unofficial Python library for Nuclei Scanner.

## Features
- Run Nuclei Scans for all or selected templates
- By default uses random User-Agents for every scan.
- User-defined rate limit (Default: 150)

## Installation

```sh
pip3 install PyNuclei
```

## Usage

```python
from PyNuclei import Nuclei
"""
nucleiScanner = Nuclei(templatePath)
Args:
    nucleiPath [str][Optional]: The path of nuclei binary file

Returns:
    PyNuclei.Nuclei class object

nucleiScanner.scan()
Args:
    host [str]: The hostname of the target which Nuclei will run against
    templates [list][Optional]: If templates list not provided all nuclei templates from "nucleiTemplates" property will be executed
    userAgents [str][Optional]: If not provided random User-Agents will be used.
    rateLimit [int][Optional]: Defaults to 150.
    maxHostError [int][Optional]: It determine to skip host for scanning after n number of connection failures
    stopAfter [int][Optional]: Stop scanning after getting n number of findings, only use for template paths instead of template categories
    metrics [bool][Optional]: It shows the scan progress. Example: 
        [PyNucleiMonitor] [INFO] Queued: 12 | Running: 4 | Done: 0 | Percentage: 4.46% | Eta: 00d 00h 00m 00s
        [PyNucleiMonitor] [INFO] Queued: 2 | Running: 10 | Done: 4 | Percentage: 10.01% | Eta: 00d 00h 00m 32s
        [PyNucleiMonitor] [INFO] Queued: 1 | Running: 11 | Done: 4 | Percentage: 13.74% | Eta: 00d 00h 03m 19s
    
    verbose [bool][Optional]: Show nuclei subprocess output and PyNuclei warning logs. Example:
        [PyNuclei] [WARN] Output directory already exist /var/folders/nk/6zwpdb0n037071f4tk9g5c1m0000gp/T/
        [Stdout] [http://honey.scanme.sh] [HTTP-TRACE:trace-request] [http] [info] http://honey.scanme.sh

        [Stderr] [http://honey.scanme.sh]
                            __     _
        ____  __  _______/ /__  (_)
        / __ \/ / / / ___/ / _ \/ /
        / / / / /_/ / /__/ /  __/ /
        /_/ /_/\__,_/\___/_/\___/_/   v3.1.5

                projectdiscovery.io

        [INF] Current nuclei version: v3.1.5 (outdated)
        [INF] Current nuclei-templates version: v9.7.3 (latest)
        [WRN] Scan results upload to cloud is disabled.
        [INF] New templates added in latest release: 46
        [INF] Templates loaded for current scan: 1
        [WRN] Executing 1 unsigned templates. Use with caution.
        [INF] Targets loaded for current scan: 1
        [0:00:00] | Templates: 1 | Hosts: 1 | RPS: 0 | Matched: 0 | Errors: 0 | Requests: 0/2 (0%)
        [0:00:01] | Templates: 1 | Hosts: 1 | RPS: 0 | Matched: 0 | Errors: 0 | Requests: 0/2 (0%)
        [0:00:01] | Templates: 1 | Hosts: 1 | RPS: 0 | Matched: 0 | Errors: 0 | Requests: 0/2 (0%)
        [0:00:01] | Templates: 1 | Hosts: 1 | RPS: 0 | Matched: 0 | Errors: 0 | Requests: 0/2 (0%)
        [0:00:02] | Templates: 1 | Hosts: 1 | RPS: 0 | Matched: 0 | Errors: 0 | Requests: 0/2 (0%)
        [0:00:02] | Templates: 1 | Hosts: 1 | RPS: 0 | Matched: 0 | Errors: 0 | Requests: 0/2 (0%)
        [0:00:02] | Templates: 1 | Hosts: 1 | RPS: 0 | Matched: 1 | Errors: 0 | Requests: 1/2 (50%)
        [0:00:03] | Templates: 1 | Hosts: 1 | RPS: 0 | Matched: 1 | Errors: 0 | Requests: 2/2 (100%)

Returns:
    result [dict]: Scan result from all templates.
"""

nucleiPath = "/opt/app/src/bin/nuclei"
nucleiScanner = Nuclei(nucleiPath)
scanResult = nucleiScanner.scan(
    "example.com", templates=["cves","network", "ssl"], rateLimit=150, 
    verbose=False, metrics=False, maxHostError=30, stopAfter=None
)
print(scanResult)
```

### Templates
```python
from PyNuclei import Nuclei

nucleiScanner = Nuclei()

"""
All active templates.
"""
print(nucleiScanner.nucleiTemplates)
[
    "cnvd", "cves", "default-logins", "exposed-panels",
    "exposures", "file", "misconfiguration",
    "miscellaneous", "takeovers", "technologies",
    "token-spray", "vulnerabilities", "network", 
    "dns", "iot", "ssl"
]

"""
All ignored templates.
"""
print(nucleiScanner.ignoredTemplates)
[
    "headless", "fuzzing", "helpers", 
]

"""
Returns details of all nuclei templates in json format
"""
print(nucleiScanner.returnTemplatesDetails())
```
NOTE: You can run ignored templates by passing them in the template parameter in ```nucleiScanner.scan(<host>, template=nucleiScanner.ignoredTemplates)```

### Update Nuclei
```python
from PyNuclei import Nuclei
"""
This will update Nuclei engine & Nuclei Templates.
"""
Nuclei.updateNuclei(verbose=True)
```

## Connect with me
<p align="left">
<a href="https://twitter.com/kushvaibhav_" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/twitter.svg" alt="kushvaibhav_" height="30" width="40" /></a>
<a href="https://linkedin.com/in/kushvaibhav" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="kushvaibhav" height="30" width="40" /></a>
<a href="https://instagram.com/kushvaibhav" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/instagram.svg" alt="kushvaibhav" height="30" width="40" /></a>
</p>
