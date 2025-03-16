# Burp Suite Extension: Access Control Checker
# This script attempts to access restricted resources by modifying parameters.

import os
import urlparse

from burp import IBurpExtender, IScannerCheck, IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Access Control Checker")
        callbacks.registerScannerCheck(self)

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Attempt to bypass access controls by modifying a parameter (example: change user id)
        issues = []
        payload = "admin=true"
        attack = insertionPoint.buildRequest(payload)
        response = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), attack)
        if b"Access Granted" in response.getResponse():
            # Build extended details using a snippet of the response for more context
            extended_details = ("Access control bypass appears possible. "
                                "Response snippet: " + response.getResponse()[:200].decode('latin1', 'ignore'))
            issues.append(CustomScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                "Broken Access Control",
                extended_details,
                "High"
            ))
            # Update or create the Markdown report file
            self.updateReport(baseRequestResponse, "Broken Access Control",
                              "Access Control Bypass",
                              extended_details, "High")
        return issues

    def doPassiveScan(self, baseRequestResponse):
        return []

    def updateReport(self, baseRequestResponse, vulnName, vulnType, detail, risk):
        # Get the target URL from the analyzed request
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl().toString()
        parsed = urlparse.urlparse(url)
        domain = parsed.hostname or "UNKNOWN"
        if domain.startswith("www."):
            domain = domain[4:]
        reportFileName = domain.upper() + "_REPORT.md"

        # Build the vulnerability entry in Markdown format
        reportEntry = "\n## Vulnerability Found: {}\n".format(vulnName)
        reportEntry += "**Title:** Security Report for {}\n".format(domain)
        reportEntry += "**Vulnerability Type:** {}\n".format(vulnType)
        reportEntry += "**Risk:** {}\n".format(risk)
        reportEntry += "**Extended Details:** {}\n".format(detail)
        reportEntry += "**Mitigation Actions:**\n\n"

        # Append or create the report file
        if os.path.exists(reportFileName):
            with open(reportFileName, "a") as f:
                f.write(reportEntry)
        else:
            with open(reportFileName, "w") as f:
                f.write("# Security Report for {}\n".format(domain))
                f.write(reportEntry)

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
