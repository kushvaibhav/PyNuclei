""" PyNuclei Module - allow running nuclei from Python """
import json
import random
import subprocess
import os
import shutil
import tempfile

from .ScanUtils.UserAgents import USER_AGENTS

FILE_SEPARATOR = "#SEP#"

class NucleiNotFound(Exception):
	pass


class Nuclei:
	"""
	Class handling the Nuclei scans and result generation.
	"""

	def __init__(self):
		Nuclei.checkFirstRun()
		self.outputPath = f"{tempfile.gettempdir()}/"
		try:
			os.makedirs(os.path.expanduser(self.outputPath))
		except FileExistsError:
			pass


	@staticmethod
	def isNucleiInstalled():
		isInstalled = shutil.which("nuclei")
		if isInstalled is None:
			raise NucleiNotFound("Nuclei not found in path")


	@staticmethod
	def checkFirstRun():
		with open(f"{os.path.dirname(__file__)}/.config", "r+", encoding="latin1") as pyNucleiConfig:
			configDetails = json.loads(pyNucleiConfig.read())
			if configDetails["FIRST_RUN"]:
				print("Configuring PyNuclei for First Run...")
				Nuclei.updateNuclei()

				configDetails["FIRST_RUN"] = False
				pyNucleiConfig.seek(0)
				pyNucleiConfig.truncate()
				pyNucleiConfig.write(json.dumps(configDetails))


	@staticmethod
	def updateNuclei(verbose=False):
		"""
		Checks and updates Nuclei.

		Checks for any updates to Nuclei or Nuclei Templates,
		and installs them if any.
		"""

		# Make sure Nuclei is installed
		Nuclei.isNucleiInstalled()

		processes = []
		commands = [
			["nuclei", "-update-templates"],
			["nuclei", "-update"]
		]

		for command in commands:
			processes.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))

		for process in processes:
			output, error = process.communicate()
			if verbose:
				print(f"[Stdout] {output.decode('utf-8', 'ignore')}")
				print(f"[Stderr] {error.decode('utf-8', 'ignore')}")


	@property
	def ignoredTemplates(self):
		return [
			"headless", "fuzzing", "helpers", 
		]


	@property
	def nucleiTemplates(self):
		return [
			"cnvd", "cves", "default-logins", "exposed-panels",
			"exposures", "file", "misconfiguration",
			"miscellaneous", "takeovers", "technologies",
			"token-spray", "vulnerabilities", "network", 
			"dns", "iot", "ssl"
		]


	def createResultDir(self, host):
		try:
			os.makedirs(os.path.expanduser(f"{self.outputPath}{host}"))
		except FileExistsError:
			pass


	def _parseNucleiScan(self, host, templates):
		report = []

		for template in templates:
			try:
				with open(f"{self.outputPath}{host}{template}", "r", encoding="latin1") as scanResult:
					report.extend(json.load(scanResult))
			except Exception as e:
				print(f"Exception while reading Nuclei Scan Result: {e}")

		return report


	def _formatNucleiReport(self, report):
		"""
		Reformats the raw Nuclei scan results from file into a cleaner list.
		Args:
			report (list): The raw report from file
		Returns:
			list: The list of formatted report
		"""
		formattedReport = []
		for vuln in report:
			try:
				data = {
					"templateId": vuln["template-id"],
					"host": vuln["host"],
					"vulnerabilityName": vuln["info"]["name"],
					"vulnerabilityDetail": str(),
					"description": str(),
					"type": vuln["type"],
					"result": [],
					"vulnerableAt": vuln["matched-at"],
					"solution": str(),
					"curl": str(),
					"severity": vuln["info"]["severity"],
					"tags": vuln["info"]["tags"],
					"reference": str(),
					"cvss-metrics": str(),
					"cvss-score": None,
					"cve-id": str(),
					"cwe-id": None
				}
				if "description" in vuln["info"]:
					data["description"] = vuln["info"]["description"]

				if "severity" in vuln["info"]:
					data["severity"] = vuln["info"]["severity"]

				if "reference" in vuln["info"]:
					if vuln["info"]["reference"]:
						if isinstance(vuln["info"]["reference"], str):
							data["reference"] = vuln["info"]["reference"]
						elif isinstance(vuln["info"]["reference"], list):
							data["reference"] =  ", ".join(vuln["info"]["reference"])

				if "remediation" in vuln["info"]:
					data["solution"] = vuln["info"]["remediation"]

				if "classification" in vuln["info"]:

					if "cvss-metrics" in vuln["info"]["classification"]:
						data["cvss-metrics"] = vuln["info"]["classification"]["cvss-metrics"]

					if "cvss-score" in vuln["info"]["classification"]:
						data["cvss-score"] = vuln["info"]["classification"]["cvss-score"]

					if "cve-id" in vuln["info"]["classification"]:
						data["cve-id"] = vuln["info"]["classification"]["cve-id"]

					if "cwe-id" in vuln["info"]["classification"]:
						cwe = 0
						if isinstance(vuln["info"]["classification"]["cwe-id"], list) and vuln["info"]["classification"]["cwe-id"]:
							cwe = vuln["info"]["classification"]["cwe-id"][0]
						else:
							cwe = vuln["info"]["classification"]["cwe-id"]

						if cwe is not None:
							if "cwe-" in cwe.lower():
								data["cwe-id"] = int(cwe.split("-")[-1])

				if "extracted-results" in vuln:
					data["result"] = vuln["extracted-results"]

				if "curl-command" in vuln:
					data["curl"] = vuln["curl-command"]

				if "matcher-name" in vuln:
					data["vulnerabilityDetail"] = vuln["matcher-name"]

				formattedReport.append(data)
			except Exception as e:
				print(f"Error in parsing Nuclei result: {e} | Data: {vuln}")
				continue

		return formattedReport


	def scan(self, host, templates=[], userAgent="", rateLimit=150, verbose=False):
		"""
		Runs the nuclei scan and returns a formatted dictionary with the results.
		Args:
			host [str]: The hostname of the target which Nuclei will run against
			templates [list][Optional]: If templates list not provided all nuclei templates from "nucleiTemplates" property will be executed
			userAgents [str][Optional]: If not provided random User-Agents will be used.
			rateLimit [int][Optional]: Defaults to 150.
		Returns:
			result [dict]: Scan result from all templates.
		"""
		Nuclei.isNucleiInstalled()

		fileNameValidHost = f"{host.replace('/', FILE_SEPARATOR)}/"
		self.createResultDir(fileNameValidHost)
		allScans = []

		if not templates:
			templates = self.nucleiTemplates

		for template in templates:
			if not userAgent:
				userAgent = random.choice(USER_AGENTS)

			command = [
				'nuclei', '-header', f"'User-Agent: {userAgent}'", 
				"-rl", str(rateLimit), "-u", host, "-t", f"{template}/", 
				"--json-export", f"{self.outputPath}{fileNameValidHost}{template}", 
				"-disable-update-check"
			]
			allScans.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))

		for process in allScans:
			output, error = process.communicate()
			if verbose:
				print(f"[Stdout] [{host}] {output.decode('utf-8', 'ignore')}")
				print(f"[Stderr] [{host}] {error.decode('utf-8', 'ignore')}")

		report = self._parseNucleiScan(fileNameValidHost, templates)

		shutil.rmtree(f"{self.outputPath}{fileNameValidHost}", ignore_errors=True)

		return self._formatNucleiReport(report)
