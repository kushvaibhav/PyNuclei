#!/usr/bin/python3
import PyNuclei

nuclei_scanner = PyNuclei.Nuclei()
templates = nuclei_scanner.returnTemplatesDetails()
print(templates)