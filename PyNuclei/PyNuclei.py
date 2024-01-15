import json
import yaml

import time
import datetime

import os
import shutil
import string
import tempfile
import requests
import threading
import subprocess

from threading import Thread
from fake_useragent import FakeUserAgent
from distutils.spawn import find_executable

FILE_SEPARATOR = "#SEP#"

class NucleiNotFound(Exception):
	pass


class Nuclei:
	"""
	Class handling the Nuclei scans and result generation.
	"""

	def __init__(self, nucleiPath=None):
		self.done = int()
		self.running = int()
		self.verbose = bool()
		self.stopAfter = None
		self.findings = int()
		self.processes = list()
		self.maxProgress = int()
		self.currentProgress = int()
		self.nucleiPath = nucleiPath
		self.selectedTemplatesCount = int()
		self.eta = datetime.timedelta(seconds=0)

		# Allow changing the path where nuclei is installed (instead of expecting it to be in $PATH)
        # Check if the '/' is at the end - and remove it if "yes"
		if nucleiPath is not None and nucleiPath[-1] == "/":
			self.nucleiPath = nucleiPath[:-1]

		self.nucleiBinary = "nuclei"
		if self.nucleiPath:
			self.nucleiBinary = f"{self.nucleiPath}/{self.nucleiBinary}"
		
		Nuclei.checkFirstRun(self.nucleiPath)
		self.outputPath = f"{tempfile.gettempdir()}/"
		try:
			os.makedirs(os.path.expanduser(self.outputPath))
		except FileExistsError:
			print(f"[PyNuclei] [WARN] Output directory already exist {self.outputPath}")


	@staticmethod
	def isNucleiInstalled(nucleiPath):
		isInstalled = find_executable("nuclei", path=nucleiPath)
		if not isInstalled:
			raise NucleiNotFound("[PyNuclei] [ERROR] Nuclei not found in path")


	@staticmethod
	def checkFirstRun(nucleiPath):
		with open(f"{os.path.dirname(__file__)}/.config", "r+") as pyNucleiConfig:
			configDetails = json.loads(pyNucleiConfig.read())
			if configDetails["FIRST_RUN"]:
				print("[PyNuclei] [INFO] Configuring PyNuclei for First Run...")
				Nuclei.updateNuclei(True, nucleiPath)

				configDetails["FIRST_RUN"] = False
				pyNucleiConfig.seek(0)
				pyNucleiConfig.truncate()
				pyNucleiConfig.write(json.dumps(configDetails))


	@staticmethod
	def updateNuclei(verbose=False, nucleiPath=None):
		"""
		Checks and updates Nuclei.

		Checks for any updates to Nuclei or Nuclei Templates,
		and installs them if any.
		"""
		Nuclei.isNucleiInstalled(nucleiPath)

		processes = list()
		nucleiBinary = "nuclei"
		if nucleiPath:
			nucleiBinary = f"{nucleiPath}/{nucleiBinary}"
		
		commands = [
			[nucleiBinary, "-update-templates"],
			[nucleiBinary, "-update"]
		]
		
		for command in commands:
			processes.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))

		for process in processes:
			output, error = process.communicate()
			if verbose:
				print(f"[Stdout] {output.decode('utf-8', 'ignore')}")
				print(f"[Stderr] {error.decode('utf-8', 'ignore')}")


	@staticmethod
	def metricsThreadCount():
		return [thread.getName() == "PyNucleiMetricThread" and thread.is_alive() for thread in threading.enumerate()].count(True)
	

	@staticmethod
	def nucleiThreadCount():
		return ["PyNucleiScanThread" in thread.getName() and thread.is_alive() for thread in threading.enumerate()].count(True)


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
			if self.verbose:
				print(f"[PyNuclei] [WARN] Result directory exist {self.outputPath}{host}")


	def stringifyTimeDelta(self, tdelta, fmt="{D:02}d {H:02}h {M:02}m {S:02}s", inputType="timedelta"):
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

		The input type argument allows time delta to be a regular number instead of the
		default, which is a datetime.timedelta object.  Valid input type strings:
			's', 'seconds',
			'm', 'minutes',
			'h', 'hours',
			'd', 'days',
			'w', 'weeks'
		"""

		# Convert time delta to integer seconds.
		if inputType == "timedelta":
			remainder = int(tdelta.total_seconds())
		elif inputType in ["s", "seconds"]:
			remainder = int(tdelta)
		elif inputType in ["m", "minutes"]:
			remainder = int(tdelta) * 60
		elif inputType in ["h", "hours"]:
			remainder = int(tdelta) * 3600
		elif inputType in ["d", "days"]:
			remainder = int(tdelta) * 86400
		elif inputType in ["w", "weeks"]:
			remainder = int(tdelta) * 604800

		f = string.Formatter()
		desiredFields = [fieldTuple[1] for fieldTuple in f.parse(fmt)]
		possibleFields = ("W", "D", "H", "M", "S")
		constants = {"W": 604800, "D": 86400, "H": 3600, "M": 60, "S": 1}
		values = dict()
		for field in possibleFields:
			if field in desiredFields and field in constants:
				values[field], remainder = divmod(remainder, constants[field])
		return f.format(fmt, **values)


	def _metricsThread(self, maxMetricsPort):
		"""Connect to the /metrics backend and make stats"""

		progressValues = dict()
		while True:
			self.done = 0
			self.running = 0

			for port in range(9092, maxMetricsPort):
				if port not in progressValues:
					progressValues[port] = {
						"max": 1,
						"current": 0,
						"matched": 0,
						"done": False,
						"eta": datetime.timedelta(seconds=0),
						"startTime": datetime.datetime.now()
					}

				try:
					response = requests.get(
						f"http://127.0.0.1:{port}/metrics", timeout=1
					)
				except (requests.ConnectionError, requests.Timeout) as _:
					# If the port is closed, then scan must be complete
					scanThreadPorts = [thread for thread in threading.enumerate() if thread.getName() == f"PyNucleiScanThread-{port}"]
					if not scanThreadPorts and port in progressValues:
						self.done += 1
						progressValues[port]["done"] = True
						progressValues[port]["current"] = progressValues[port]["max"]

					continue

				responseObj = dict()
				self.running += 1
				try:
					responseObj = response.json()
				except Exception as _:
					if self.verbose:
						print(f"[PyNucleiMetrics] [WARN] - Unable to decode response from http://127.0.0.1:{port}/metrics")

					continue

				progressValues[port]["done"] = False
				progressValues[port]["max"] = responseObj["total"]
				progressValues[port]["matched"] = responseObj["matched"]
				progressValues[port]["current"] = responseObj["requests"]

			self.findings = 0
			self.maxProgress = 0
			self.currentProgress = 0
			self.eta = datetime.timedelta(seconds=0)

			for _, item in progressValues.items():
				self.maxProgress += item["max"]
				self.findings += item["matched"]
				self.currentProgress += item["current"]
				if item["eta"] > self.eta:
					self.eta = item["eta"]

				if item["current"] and item["max"]:
					item["eta"] = datetime.timedelta(seconds=0)
					if not item["done"]:
						progress = item["current"] / item["max"] * 100.0
						if progress != 100:
							now = datetime.datetime.now()
							item["eta"] = (now - item["startTime"]) / progress * (100 - progress)
				
			if not self.running and self.done == (maxMetricsPort - 9092):
				break # No more running scans

			time.sleep(0.5)


	def _monitorProgress(self):
		while True:
			if self.maxProgress == 0:
				time.sleep(0.5) 	# Waiting for threads to spawn
				continue

			if self.stopAfter and self.findings >= self.stopAfter:
				print(f"[PyNucleiMonitor] [INFO] Stopping nuclei processes, finding count: {self.findings}")
				time.sleep(1) 		# Waiting for nuclei processes to generate result
				self.stop()
			
			else:
				queuedScans = self.nucleiThreadCount() - self.running
				scanPercentage = f"{self.currentProgress/self.maxProgress * 100.0:.2f}%"
				if queuedScans < 0:
					queuedScans = int()

				if queuedScans + self.running + self.done != self.selectedTemplatesCount:
					time.sleep(1) 	# Waiting for threads to spawn
					continue 		# Avoid logs with wrong values

				print(
					f"[PyNucleiMonitor] [INFO] Queued: {queuedScans} | " + \
					f"Running: {self.running} | Done: {self.done} | " + \
					f"Percentage: {scanPercentage} | Eta: {self.stringifyTimeDelta(self.eta)}"
				)

			if not self.nucleiThreadCount() and not self.metricsThreadCount():
				break

			time.sleep(1) 			# Waiting for threads to spawn


	def _nucleiThread(self, host, command, verbose):
		"""Launch the nuclei process and output the outcome if 'verbose'"""
		process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.processes.append(process)

		output, error = process.communicate()
		if verbose:
			print(f"[Stdout] [{host}] {output.decode('utf-8', 'ignore')}")
			print(f"[Stderr] [{host}] {error.decode('utf-8', 'ignore')}")


	def _parseNucleiScan(self, host, templates):
		"""Parse nuclei scan results in json object"""
		
		report = list()
		for template in templates:
			try:
				templateOutputPath = f"{self.outputPath}{host}{template}"
				if ".yaml" in template or ".yml" in template:
					templateOutputPath = f"{self.outputPath}{host}{template.split('/')[-1].split('/')[0]}"

				with open(templateOutputPath, "r") as scanResult:
					report.extend(json.load(scanResult))

			except FileNotFoundError:
				if self.verbose:
					print(f"[PyNucleiParser] [ERROR] File not found for {templateOutputPath}")
			
			except Exception as e:
				print(f"[PyNucleiParser] [ERROR] : {e}")

		return report


	def _formatNucleiReport(self, report):
		"""
		Reformats the raw Nuclei scan results from file into a cleaner list.
		Args:
			report (list): The raw report from file
		Returns:
			list: The list of formatted report
		"""
		formattedReport = list()
		for vuln in report:
			try:
				data = {
					"templateId": vuln["template-id"],
					"host": vuln["host"],
					"vulnerabilityName": vuln["info"]["name"],
					"vulnerabilityDetail": str(),
					"description": str(),
					"type": vuln["type"],
					"result": list(),
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
								data["cwe-id"] = int(cwe.split("-")[-1]) if cwe.split("-")[-1].isnumeric() else int()
					
				if "extracted-results" in vuln:
					data["result"] = vuln["extracted-results"]

				if "curl-command" in vuln:
					data["curl"] = vuln["curl-command"]

				if "matcher-name" in vuln:
					data["vulnerabilityDetail"] = vuln["matcher-name"]

				formattedReport.append(data)
			
			except Exception as e:
				print(f"[PyNucleiResultFormatter] [ERROR] : {e}")
				continue
		
		return formattedReport


	def returnTemplatesDetails(self):
		"""
		Process the templates available and return them as a structure
		WARNING: This is a VERY time consuming function
		"""		
		command = ["nuclei", "--no-color", "--template-display"]

		process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output, _ = process.communicate()
		output = output.decode()

		templates = list()
		startTemplate = output.find("Template: ")
		while startTemplate != -1:
			endTemplate = output.find("# digest: ", startTemplate)
			if endTemplate == -1 and not templates:
				raise ValueError("Cannot find '# digest: ")

			template = output[startTemplate:endTemplate]
			templateObj = yaml.safe_load(template)

			keys = list(templateObj.keys())
			for key in keys:
				# Keep only the info we want
				if key not in ["Template", "id", "info"]:
					del templateObj[key]

			templates.append(templateObj)

			# Reducing the size of 'output' is very time consuming, we will avoid it
			startTemplate = output.find("Template: ", endTemplate)

		return templates
	

	def stop(self):
		"""Allow stopping of nuclei processes"""
		for process in self.processes:
			process.send_signal(2)  # SIGINT


	def scan(self, host, templates=list(), userAgent="", rateLimit=150, verbose=False, metrics=False, maxHostError=30, stopAfter=None):
		"""
		Runs the nuclei scan and returns a formatted dictionary with the results.
		Args:
			host [str]: The hostname of the target which Nuclei will run against
			templates [list][Optional]: If templates list not provided all nuclei templates from "nucleiTemplates" property will be executed
			userAgents [str][Optional]: If not provided random User-Agents will be used.
			rateLimit [int][Optional]: Defaults to 150.
			metrics [bool][Optional]: It shows the scan progress
			maxHostError [int][Optional]: It determine to skip host for scanning after n number of connection failures
			stopAfter [int][Optional]: Stop scanning after getting n number of findings, only use for template paths instead of template categories
		
		Returns:
			result [dict]: Scan result from all templates.
		"""

		Nuclei.isNucleiInstalled(self.nucleiPath)

		self.verbose = verbose
		self.stopAfter = stopAfter

		if self.stopAfter:
			print("[PyNuclei] [WARN] Use stopAfter optional parameter only for templates, not for template categories")
		
		fileNameValidHost = f"{host.replace('/', FILE_SEPARATOR)}/"
		if not templates:
			templates = self.nucleiTemplates

		self.createResultDir(fileNameValidHost)

		commands = list()
		metricsPort = 9092
		self.selectedTemplatesCount = len(templates)
		
		for template in templates:
			if not userAgent:
				userAgent = FakeUserAgent.random

			templateOutputPath = f"{self.outputPath}{fileNameValidHost}{template}"
			if ".yaml" in template or ".yml" in template:
				templateOutputPath = f"{self.outputPath}{fileNameValidHost}{template.split('/')[-1].split('/')[0]}"

			command = [
				self.nucleiBinary, '-header', f"'User-Agent: {userAgent}'", 
				"-rl", str(rateLimit), "-u", host, "-t", template if ".yaml" in template or ".yml" in template else f"{template}/",
				"--json-export", templateOutputPath, 
				"-disable-update-check"
			]

			if maxHostError != 30:
				command.extend(["-max-host-error", str(maxHostError)])

			if metrics:
				command.extend([
					"-stats", "-metrics-port", str(metricsPort),
					"-stats-interval", "1" # Update very 1 second
				])
				metricsPort += 1

			commands.append(command)

		threads = list()
		for command in commands:
			threadMetricsPort = command[command.index("-metrics-port") + 1] if metrics else None
			threadName = f"PyNucleiScanThread-{threadMetricsPort}" if threadMetricsPort else "PyNucleiScanThread"
			scanThread = Thread(name=threadName, target=self._nucleiThread, args=[host, command, self.verbose])
			threads.append(scanThread)
			scanThread.start()

		if metrics:
			monitorThread = Thread(name="PyNucleiMonitorThread", target=self._monitorProgress)
			metricsThread = Thread(name="PyNucleiMetricThread", target=self._metricsThread, args=[metricsPort])
			threads.extend([monitorThread, metricsThread])
			metricsThread.start() # Starting metrics thread before monitorThread
			monitorThread.start()

		for thread in threads:
			thread.join()

		report = self._parseNucleiScan(fileNameValidHost, templates)

		shutil.rmtree(f"{self.outputPath}{fileNameValidHost}", ignore_errors=True)

		return self._formatNucleiReport(report)