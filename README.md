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
Nuclei(templatePath)
Args:
    nucleiPath [str][Optional]: The path of nuclei binary file

Returns:
    PyNuclei.Nuclei class object

nucleiScanner.scan()
Args:
    host [str]: The hostname of the target which Nuclei will run against
    templates [list][Optional]: If the templates list is not provided all nuclei templates from the "nucleiTemplates" property will be executed
    userAgents [str][Optional]: If not provided random User-Agents will be used.
    rateLimit [int][Optional]: Defaults to 150.
    maxHostError [int][Optional]: It determines to skip host for scanning after n number of connection failures
    stopAfter [int][Optional]: Stop scanning after getting n number of findings, only use for template paths instead of template categories
    metrics [bool][Optional]: It shows the scan progress.   
    verbose [bool][Optional]: Show nuclei results output and PyNuclei warning logs.

Returns:
    result [dict]: Scan results from all templates.
"""

nucleiPath = "/opt/app/src/bin/nuclei"
nucleiScanner = Nuclei(nucleiPath)
scanResult = nucleiScanner.scan(
    "example.com",
    templates=["cves", "network", "ssl"],
    rateLimit=150, 
    verbose=False,
    metrics=False,
    maxHostError=30,
    stopAfter=None
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
Returns details of all nuclei templates in JSON format
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
