# Burp Suite Extension: Insecure Deserialization Tester
# This script sends crafted serialized payloads to test for insecure deserialization vulnerabilities.

from burp import IBurpExtender, IScannerCheck, IScanIssue
import os
import urlparse

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Deserialization Tester")
        callbacks.registerScannerCheck(self)

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        issues = []
        # A sample serialized payload (this is a dummy payload for demonstration)
        payload = "O:8:\"Exploit\":1:{s:4:\"test\";s:4:\"data\";}"
        attack = insertionPoint.buildRequest(payload)
        response = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), attack)
        if b"Exception" in response.getResponse():
            vuln_name = "Insecure Deserialization"
            vuln_type = "Deserialization Vulnerability"
            detail = "Response indicates potential insecure deserialization. Extended details: Exception encountered during payload processing."
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
