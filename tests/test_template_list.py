#!/usr/bin/python3
import os
import sys

# Include the PyNuclei path so that we can use the classes found in it
sys.path.append("../PyNuclei")
import PyNuclei

NUCLEI_PATH = f"{os.getcwd()}/bin"
nuclei_scanner = PyNuclei.Nuclei(NUCLEI_PATH)

templateDetails = nuclei_scanner.returnTemplatesDetails()
print(templateDetails)