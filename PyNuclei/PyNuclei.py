""" PyNuclei Module - allow running nuclei from Python """
import json
import random
import subprocess
import os
import shutil
import tempfile
from threading import Thread
import time
import requests
import datetime

from .ScanUtils.UserAgents import USER_AGENTS

FILE_SEPARATOR = "#SEP#"


class NucleiNotFound(Exception):
    """
    Exception for not finding Nuclei in the system
    """


class Nuclei:
    """
    Class handling the Nuclei scans and result generation.
    """

    def __init__(self):
        self.running = 0
        self.done = 0
        self.current_progress = 0
        self.max_progress = 0
        self.eta = 0
        self.verbose = False

        Nuclei.check_first_run()
        self.output_path = f"{tempfile.gettempdir()}/"
        try:
            os.makedirs(os.path.expanduser(self.output_path))
        except FileExistsError:
            pass

    def metrics_thread(self, max_metrics_port):
        """Connect to the /metrics backend and make stats from it"""

        start_time = datetime.datetime.now()
        while True:
            self.current_progress = 0
            self.max_progress = 0
            self.running = 0
            self.done = 0
            self.eta = 0

            for port in range(9092, max_metrics_port):
                try:
                    response = requests.get(
                        f"http://127.0.0.1:{port}/metrics", timeout=1
                    )
                except requests.ConnectionError as _:
                    self.done += 1
                    continue

                json_object = {}

                # If the port is closed, then the process is done
                # If there is a malformed JSON, we don't really know
                try:
                    json_object = response.json()
                    self.running += 1
                except Exception as _:
                    self.done += 1
                    continue

                self.current_progress += json_object["requests"]
                self.max_progress += json_object["total"]

            current_time = datetime.datetime.now()
            total_time = current_time - start_time
            if (self.current_progress + self.running) > 0:
                estimated_remaining = (
                    total_time
                    * (self.max_progress + self.done)
                    / (self.current_progress + self.running)
                )
                self.eta = estimated_remaining

            if self.verbose:
                print(
                    f"{self.running=} {self.done=} {self.current_progress}/{self.max_progress}"
                )
            time.sleep(1)  # Sleep for 1sec

    def scanning_thread(self, host, command, verbose):
        """Launch the nuclei process and output the outcome if 'verbose'"""
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        output, error = process.communicate()
        if verbose:
            print(f"[Stdout] [{host}] {output.decode('utf-8', 'ignore')}")
            print(f"[Stderr] [{host}] {error.decode('utf-8', 'ignore')}")

    @staticmethod
    def is_nuclei_installed():
        """Checks whether Nuclei is installed"""
        is_installed = shutil.which("nuclei")
        if is_installed is None:
            raise NucleiNotFound("Nuclei not found in path")

    @staticmethod
    def check_first_run():
        """
        Checks if the PyNuclei module was run for the first time - if yes, update the templates
        """
        with open(
            f"{os.path.dirname(__file__)}/.config", "r+", encoding="latin1"
        ) as py_nuclei_config:
            config_details = json.loads(py_nuclei_config.read())
            if config_details["FIRST_RUN"]:
                print("Configuring PyNuclei for First Run...")
                Nuclei.update_nuclei()

                config_details["FIRST_RUN"] = False
                py_nuclei_config.seek(0)
                py_nuclei_config.truncate()
                py_nuclei_config.write(json.dumps(config_details))

    @staticmethod
    def update_nuclei():
        """
        Checks and updates Nuclei.

        Checks for any updates to Nuclei or Nuclei Templates,
        and installs them if any.
        """

        # Make sure Nuclei is installed
        Nuclei.is_nuclei_installed()

        processes = []
        commands = [["nuclei", "-update-templates"], ["nuclei", "-update"]]

        for command in commands:
            processes.append(
                subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            )

        for process in processes:
            output, error = process.communicate()
            if self.verbose:
                print(f"[Stdout] {output.decode('utf-8', 'ignore')}")
                print(f"[Stderr] {error.decode('utf-8', 'ignore')}")

    @property
    def ignored_templates(self):
        """Ignore slow and helper templates"""
        return [
            "headless",
            "fuzzing",
            "helpers",
        ]

    @property
    def nuclei_templates(self):
        """Return a list of usable templates"""
        return [
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
        ]

    def create_result_dir(self, host):
        """Create the result directory nuclei will use"""
        try:
            os.makedirs(os.path.expanduser(f"{self.output_path}{host}"))
        except FileExistsError:
            pass

    def _parse_nuclei_scan(self, host, templates):
        report = []

        for template in templates:
            try:
                with open(
                    f"{self.output_path}{host}{template}", "r", encoding="latin1"
                ) as scan_result:
                    report.extend(json.load(scan_result))
            except Exception as e:
                print(f"Exception while reading Nuclei Scan Result: {e}")

        return report

    def _format_nuclei_report(self, report):
        """
        Reformats the raw Nuclei scan results from file into a cleaner list.
        Args:
                report (list): The raw report from file
        Returns:
                list: The list of formatted report
        """
        formatted_report = []
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
                    "cwe-id": None,
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
                            data["reference"] = ", ".join(vuln["info"]["reference"])

                if "remediation" in vuln["info"]:
                    data["solution"] = vuln["info"]["remediation"]

                if "classification" in vuln["info"]:
                    if "cvss-metrics" in vuln["info"]["classification"]:
                        data["cvss-metrics"] = vuln["info"]["classification"][
                            "cvss-metrics"
                        ]

                    if "cvss-score" in vuln["info"]["classification"]:
                        data["cvss-score"] = vuln["info"]["classification"][
                            "cvss-score"
                        ]

                    if "cve-id" in vuln["info"]["classification"]:
                        data["cve-id"] = vuln["info"]["classification"]["cve-id"]

                    if "cwe-id" in vuln["info"]["classification"]:
                        cwe = 0
                        if (
                            isinstance(vuln["info"]["classification"]["cwe-id"], list)
                            and vuln["info"]["classification"]["cwe-id"]
                        ):
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

                formatted_report.append(data)
            except Exception as e:
                print(f"Error in parsing Nuclei result: {e} | Data: {vuln}")
                continue

        return formatted_report

    def scan(
        self,
        host,
        templates=[],
        user_agent="",
        rate_limit=150,
        verbose=False,
        metrics=False,
    ):
        """
        Runs the nuclei scan and returns a formatted dictionary with the results.
        Args:
                host [str]: The hostname of the target which Nuclei will run against
                templates [list][Optional]: If templates list not provided all nuclei templates from
                                                                        "nuclei_templates" property will be executed
                user_agents [str][Optional]: If not provided random User-Agents will be used.
                rate_limit [int][Optional]: Defaults to 150.
        Returns:
                result [dict]: Scan result from all templates.
        """
        self.verbose = verbose
        Nuclei.is_nuclei_installed()

        file_name_valid_host = f"{host.replace('/', FILE_SEPARATOR)}/"
        self.create_result_dir(file_name_valid_host)

        if not templates:
            templates = self.nuclei_templates

        commands = []
        metrics_port = 9092
        for template in templates:
            if not user_agent:
                user_agent = random.choice(USER_AGENTS)

            command = [
                "nuclei",
                "-header",
                f"'User-Agent: {user_agent}'",
                "-rl",
                str(rate_limit),
                "-u",
                host,
                "-t",
                f"{template}/",
                "--json-export",
                f"{self.output_path}{file_name_valid_host}{template}",
                "-disable-update-check",
            ]
            if metrics:
                command.append("-stats")
                command.append("-metrics-port")
                command.append(str(metrics_port))
                command.append("-stats-interval")
                command.append("1")  # Update very 1 second
                metrics_port += 1

            commands.append(command)

        threads = []
        for command in commands:
            t = Thread(target=self.scanning_thread, args=[host, command, self.verbose])
            threads.append(t)
            t.start()

        if metrics:
            t = Thread(target=self.metrics_thread, args=[metrics_port])
            threads.append(t)
            t.start()

        for thread in threads:
            thread.join()

        report = self._parse_nuclei_scan(file_name_valid_host, templates)

        shutil.rmtree(f"{self.output_path}{file_name_valid_host}", ignore_errors=True)

        return self._format_nuclei_report(report)
