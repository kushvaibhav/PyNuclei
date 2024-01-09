#!/usr/bin/python3
import os
import sys

# Include the PyNuclei path so that we can use the classes found in it
sys.path.append("../PyNuclei")
import PyNuclei

home_folder = os.path.expanduser("~")
nuclei_scanner = PyNuclei.Nuclei(nuclei_path=f"{home_folder}/go/bin")

templates = nuclei_scanner.return_templates_details()
