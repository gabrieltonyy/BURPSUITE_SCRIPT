# Burp Suite Extension: Sensitive Data Detector
# This script scans responses for keywords indicating sensitive information exposure.

from burp import IBurpExtender, IScannerCheck, IScanIssue
import os
import urlparse

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Sensitive Data Detector")
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        response = self._helpers.bytesToString(baseRequestResponse.getResponse())
        keywords = ["password", "credit card", "ssn", "social security"]
        for keyword in keywords:
            if keyword in response.lower():
                vuln_name = "Sensitive Data Exposure"
                vuln_type = "Sensitive Data Leak"
                detail = "Found possible sensitive data keyword: " + keyword
                risk = "High"
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    vuln_name,
                    detail,
                    risk
                ))
                # Update or create the Markdown report file
                self.updateReport(baseRequestResponse, vuln_name, vuln_type, detail, risk)
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
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

        # Append to or create the report file
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
