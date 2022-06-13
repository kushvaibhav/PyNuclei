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
nucleiScanner.scan()
Args:
    host [str]: The hostname of the target which Nuclei will run against
    templates [list][Optional]: If templates list not provided all nuclei templates from "nucleiTemplates" property will be executed
    userAgents [str][Optional]: If not provided random User-Agents will be used.
    rateLimit [int][Optional]: Defaults to 150.
Returns:
    result [dict]: Scan result from all templates.
"""

nucleiScanner = Nuclei()
scanResult = nucleiScanner.scan("example.com", template=["cves","network", "ssl"], rateLimit=150))
print(scanResult)
```

## Connect with me
<p align="left">
<a href="https://twitter.com/kushvaibhav_" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/twitter.svg" alt="kushvaibhav_" height="30" width="40" /></a>
<a href="https://linkedin.com/in/kushvaibhav" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="kushvaibhav" height="30" width="40" /></a>
<a href="https://instagram.com/kushvaibhav" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/instagram.svg" alt="kushvaibhav" height="30" width="40" /></a>
</p>
