import json
from json import dumps
import requests
from requests import Session
from sys import argv, exit, version
from argparse import ArgumentParser
import time
import datetime
import re

class janitorScript(object):
    def __init__(self):
        self.arg = self.parse_args()
        if len(argv) != 4:
            print("wrong argument amount. see HELP")
            exit(-6)
        self._headers = {}
        self.title_column = 0      # 'title' column  in csv required for all exports
        self.node_name_column = 0  # 'node_name' column in csv required for both nodes exports
        self.issue_id_column = 0   # 'issue_id' column in csv required for nodes w/evidence exports
        # Dradis API Configuration
        self.verify_cert = True    # change this to make requests without verifying
        self.dradis_api_token = self.arg.dradis_api_token
        self.dradis_project_id = self.arg.dradis_project_id
        self.dradis_url = self.arg.dradis_url
        self.dradis_issues_url = '{0}/pro/api/issues/'.format(self.dradis_url)
        self.dradis_evidence_url = '{0}/pro/api/evidence/'.format(self.dradis_url)
        self.dradis_nodes_url = '{0}/pro/api/nodes/'.format(self.dradis_url)
        self.session = Session()
        self.session.headers.update({'Authorization': 'Token token="{0}"'.format(self.dradis_api_token)})
        self.session.headers.update({'Dradis-Project-Id': self.dradis_project_id})
        self.session.headers.update({'Content-type': 'application/json'})
    
    def run(self):
        try:
            self.issueCleaner()
        except Exception as e:
            print('Failed in run: {0}'.format(e))
            exit(-1)
        self.session.close()
        return 0

    def issueCleaner(self):
        # Remove bad XML characters from Dradis issues
        today = str(datetime.datetime.now())
        newCveSite = 'https://cvedetails.com/cve/'
        refPattern = re.compile(r'References')
        cvePattern = re.compile(r'CVE_ID')
        cwePattern = re.compile(r'CWE_ID')
        modulePattern = re.compile(r'Module_OTGv4')
        touchedByPattern = re.compile(r'Touched_By')
        # HTTP GET request headers
        headers = {'Authorization': 'Token token={0}'.format(self.dradis_api_token), 'Dradis-Project-Id': self.dradis_project_id}

		# HTTP PUT request headers
        putHeaders = {'Authorization': 'Token token={0}'.format(self.dradis_api_token), 'Dradis-Project-Id': self.dradis_project_id, 'Content-Type':'application/json'}

        # HTTP GET request to get all issues in the specified Dradis project
        response = self.session.get(self.dradis_issues_url, headers=headers, verify=self.verify_cert)

        # If the above GET request returns 200 code, let the user know, otherwise say what's wrong
        if '[200]' in str(response):
            print('HTTP 200 OK')
        else:
            print('Did not receive HTTP 200 code, probably incorrect Dradis url argument. ' + str(response))
        
        # Convert the GET response into a JSON object which will be interpreted by Python as a dict, lovely
        issues = response.json()
        
        # Print the response body (all issues in Dradis) to show that it works (hopefully)
        #print(issues)

        # Loop over every primary issue (highest level JSON object) in the dict containing all Dradis issues
        for issue in issues:
            # Loop over every field and value within each Dradis issue
            issueTitle = ''
            issueImpact = ''
            issueEase = ''
            issueRisk = ''
            issueConfidentiality = ''
            issueIntegrity = ''
            issueAvailability = ''
            issueCvss = ''
            issueAuthentication = ''
            issueSummary = ''
            issueInsight = ''
            issueMitigation = ''
            issueRiskStatus = ''
            issueThreatAgent = ''
            issueGainedAccess = ''
            issueVulnType = ''
            issueTouchedBy = ''
            issueCveId = ''
            issueCweId = ''
            issueModules = ''
            impact = ''
            impactList = []
            confidentiality = ''
            confidentialityList = []
            integrity = ''
            integrityList = []
            availability = ''
            availabilityList = []
            ease = ''
            easeList = []
            authentication = ''
            authenticationList = []
            threatAgent = ''
            gainedAccess = ''
            gainedAccessList = []
            vulnType = ''
            vulnTypeList = []
            risk = ''
            cveNum = ''
            cweNum = ''
            cweList = []
            cvss = ''
            cvssList = []
            cweField = '\r\n#[CWE_ID]#\r\n'
            cveField = '\r\n#[CVE_ID]#\r\n'
            refContainer = ''
            issueText = ''
            frankenstein = ''
            cveList = []
            cveSiteList = []
            endOfIssue = 0
            realEndOfIssue = 0
            for key, value in issue.items():
                # Code to find issue ID, which is used to identify the issue and is used in the PUT URL, very important
                if key == 'id':
                    issue_id = str(issue[key])
                    dradis_issue_url = self.dradis_issues_url + '/' + issue_id

                # Storing current issue title, for debugging
                if key == 'title':
                    issue_title = str(issue[key]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;")
                    issueTitle = "#[Title]#\r\n" + issue_title + "\r\n\r\n"
                #print('KEY: ' + str(key) + ' VALUE: ' + str(value))  # Listing every issue field and value just to show that it is working

                # Appending the entirety of the current issue into a string variable
                if key == 'text':
                    issueText = str(issue[key]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;")
                    realEndOfIssue = len(issueText)
                    myEnd = re.search(modulePattern, issue[key])
                    touchMe = re.search(touchedByPattern, issue[key])
                    if not touchMe:
                        if myEnd:
                            x = myEnd.start() - 2
                            y = myEnd.end() + 2
                            endOfIssue = len(issueText) - x
                            issueModules = myEnd.string[x:]
                        else:
                            issueModules = "#[Module_OTGv4]#\r\n\r\n#[Module_PCIDSS32]#\r\n\r\n#[Module_HIPAA]#\r\n\r\n#[Module_NIST53]#\r\n\r\n#[Module_ISO27K2013]#\r\n\r\n#[Module_GDPR2016]#\r\n\r\n#[Touched_By]#\r\nCVE_Bot_" + today + "\r\n\r\n"
                    else:
                        a = touchMe.start() - 2
                        b = touchMe.end() + 2
                        if myEnd:
                            y = myEnd.start() - 2
                            z = myEnd.end() + 2
                            issueModules = myEnd.string[y:z]
                        else:
                            issueModules = "#[Module_OTGv4]#\r\n\r\n#[Module_PCIDSS32]#\r\n\r\n#[Module_HIPAA]#\r\n\r\n#[Module_NIST53]#\r\n\r\n#[Module_ISO27K2013]#\r\n\r\n#[Module_GDPR2016]#\r\n\r\n"

                # 'Fields' is a JSON parameter that contains its own JSON parameters, so it is its own dict. Loop over it to dig inside each issue.
                if key == 'fields':
                    fields = value
                    # Looping over every key and value of the fields dict
                    for cey, falue in fields.items():
                        #print('CEY: ' + str(cey) + ' FALUE: ' + str(falue) + '\n\n')  # Debug output
                        if cey == 'Impact':
                            issueImpact = "#[Impact]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"
                            impact = str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;")

                        if cey == 'Ease':
                            issueEase = "#[Ease]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"
                            ease = str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;")

                        if cey == 'Confidentiality_Impact':
                            issueConfidentiality = "#[Confidentiality_Impact]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Integrity_Impact':
                            issueIntegrity = "#[Integrity_Impact]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Availability_Impact':
                            issueAvailability = "#[Availability_Impact]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Risk':
                            issueRisk = "#[Risk]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"
                            risk = str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;")

                        if cey == 'Authentication':
                            issueAuthentication = "#[Authentication]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Summary':
                            issueSummary = "#[Summary]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Insight':
                            issueInsight = "#[Insight]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Mitigation':
                            issueMitigation = "#[Mitigation]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Risk_Status':
                            issueRiskStatus = "#[Risk_Status]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Threat_Agent':
                            issueThreatAgent = "#[Threat_Agent]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Gained_Access':
                            issueGainedAccess = "#[Gained_Access]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Vulnerability_Type':
                            issueVulnType = "#[Vulnerability_Type]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'References':
                            issueReferences = "#[References]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        # Getting CVSS score, will check to see if it's already in the issue first
                        if cey == 'CVSS':
                            issueCvss = "#[CVSS]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"

                        if cey == 'Touched_By':
                            issueTouchedBy = "#[Touched_By]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\nJanitor_Bot_" + today + "\r\n\r\n"

            if "janitor_bot" not in issueTouchedBy.lower():
                issueTouchedBy = "#[Touched_By]#\r\nCVE_Bot_" + today + "\r\n\r\n"

            frankenstein = issueTitle + issueImpact + issueConfidentiality + issueIntegrity + issueAvailability + issueEase + issueRisk + issueAuthentication + issueCvss + issueSummary + issueInsight + issueMitigation + issueRiskStatus + issueThreatAgent + issueGainedAccess + issueVulnType + issueReferences + issueCveId + issueCweId + issueModules + issueTouchedBy

            # This is the only way to do PUT or POST requests with Dradis API
            issue_data = {'issue': {"text": frankenstein}}

            # The almighty HTTP PUT request to edit issues
            dradis = requests.put(dradis_issue_url, data=dumps(issue_data), headers=putHeaders, verify=self.verify_cert)
            if dradis.status_code == 200:
                print("Successfully cleaned up the following issue: " + issue_title)
            else:
                print("Failed to clean up the following issue: \n\n{1}\nStatus Code: {2}\n\n".format(dradis.status_code, dradis.text))
        return

    def evidenceCleaner(self):
        # Removing bad XML characters from evidence in Dradis project
        # HTTP GET request headers
        headers = {'Authorization': 'Token token={0}'.format(self.dradis_api_token), 'Dradis-Project-Id': self.dradis_project_id}

		# HTTP PUT request headers
        putHeaders = {'Authorization': 'Token token={0}'.format(self.dradis_api_token), 'Dradis-Project-Id': self.dradis_project_id, 'Content-Type':'application/json'}

        # HTTP GET request to get all issues in the specified Dradis project
        response = self.session.get(self.dradis_evidence_url, headers=headers, verify=self.verify_cert)

        # If the above GET request returns 200 code, let the user know, otherwise say what's wrong
        if '[200]' in str(response):
            print('HTTP 200 OK')
        else:
            print('Did not receive HTTP 200 code, probably incorrect Dradis url argument. ' + str(response))
        
        # Convert the GET response into a JSON object which will be interpreted by Python as a dict, lovely
        evidences = response.json()

        # Loop over every primary issue (highest level JSON object) in the dict containing all Dradis issues
        for evidence in evidences:
            # Loop over every field and value within each Dradis evidence
            issueResult = ''
            issueTitle = ''
            issue_id = ''
            evidenceText = ''
            evidenceResult = ''
            for key, value in evidence.items():
                # Code to find issue ID, which is used to identify the issue and is used in the PUT URL, very important
                if key == 'id':
                    issue_id = str(issue[key])
                    dradis_issue_url = self.dradis_issues_url + '/' + issue_id

                # Storing current issue title, for debugging
                if key == 'title':
                    issue_title = str(issue[key]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;")
                    issueTitle = "#[Title]#\r\n" + issue_title + "\r\n\r\n"
                #print('KEY: ' + str(key) + ' VALUE: ' + str(value))  # Listing every issue field and value just to show that it is working

                # Appending the entirety of the current issue into a string variable
                if key == 'text':
                    evidenceText = str(evidence[key]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;")

                # 'Fields' is a JSON parameter that contains its own JSON parameters, so it is its own dict. Loop over it to dig inside each issue.
                if key == 'fields':
                    fields = value
                    # Looping over every key and value of the fields dict
                    for cey, falue in fields.items():
                        if cey == 'Result':
                            evidenceResult = "#[Result]#\r\n" + str(fields[cey]).replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\r\n\r\n"
                            
            frankenstein = evidenceResult

            # This is the only way to do PUT or POST requests with Dradis API
            issue_data = {'issue': {"text": frankenstein}}

            # The almighty HTTP PUT request to edit issues
            dradis = requests.put(dradis_evidence_url, data=dumps(issue_data), headers=putHeaders, verify=self.verify_cert)
            if dradis.status_code == 200:
                print("Successfully cleaned up evidence for the following issue:  " + issue_title)
            else:
                print("Failed cleaning up evidence for the following issue: \n\n{1}\nStatus Code: {2}\n\n".format(dradis.status_code, dradis.text))
        return

    @staticmethod
    def parse_args():
        # parse the arguments
        parser = ArgumentParser(epilog='\tExample: \r\npython ' + argv[0] +
                                       " https://dradis.govanguard.co/ 21 xa632ghas87d393287",
                                description="Remove bad XML characters from Dradis issues")
        parser.add_argument('dradis_url', help="Dradis URL")
        parser.add_argument('dradis_project_id', help="Dradis Project ID")
        parser.add_argument('dradis_api_token', help="Dradis API token")
        return parser.parse_args()

if __name__ == "__main__":
    start_time = time.time()
    c = janitorScript()
    c.run()
    print("\n\n%s seconds" % (time.time() - start_time))
