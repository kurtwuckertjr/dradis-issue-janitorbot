from pydradis3 import Pydradis3
from json import dumps
from sys import argv, exit, version
from argparse import ArgumentParser
import time
import datetime
import re

class IssueJanitorScript(object):
    def __init__(self):
        self.arg = self.processArguments()
        if len(argv) != 4:
            print("Possibly missing arguments. Try HELP")
            exit(-6)
        # Dradis API Configuration
        self.verifyCert = True    # change this to make requests without verifying
        self.dradisApiToken = self.arg.dradisApiToken
        self.dradisProjectId = self.arg.dradisProjectId
        self.dradisUrl = self.arg.dradisUrl
        self.dradisDebug = False
        self.dradisSession = Pydradis3(self.dradisApiToken, self.dradisUrl, self.dradisDebug, self.verifyCert)
    
    def run(self):
        try:
            self.issueCleaner(self.dradisProjectId)
        except Exception as e:
            print('Failed in run: {0}'.format(e))
            exit(-1)
        self.dradisSession = None
        return 0

    def stripTrash(self, dirtyText: str):
        sanitizedText = dirtyText.replace('"','&quot;').replace("'","&apos;").replace("<","&lt;").replace(">","&gt;").replace("&","&amp;")
        return sanitizedText

    def issueCleaner(self, projectId):
        # Remove bad XML characters from Dradis issues
        today = str(datetime.datetime.now())
        newCveSite = 'https://cvedetails.com/cve/'
        refPattern = re.compile(r'References')
        cvePattern = re.compile(r'CVE_ID')
        cwePattern = re.compile(r'CWE_ID')
        modulePattern = re.compile(r'Module_OTGv4')
        touchedByPattern = re.compile(r'Touched_By')

        issueList = self.dradisSession.get_issuelist(pid=projectId)

        # Loop over every primary issue (highest level JSON object) in the dict containing all Dradis issues
        for issueEntry in issueList:
            issueId = issueEntry[1]
            print("Sanitizing issue {0}...".format(issueId))
            issue = self.dradisSession.get_issue(pid=projectId, issue_id=issueId)
            sanitizedFields = []
            # Loop over every field and value within each Dradis issue
            issueTitle = issueModules = issueText = frankenstein = '' 
            cweField = '\r\n#[CWE_ID]#\r\n'
            cveField = '\r\n#[CVE_ID]#\r\n'
            endOfIssue = realEndOfIssue = 0
            for key, value in issue.items():
                # Storing current issue title, for debugging
                if key == 'title':
                    issue_title = self.stripTrash(str(issue[key]))
                    issueTitle = "#[Title]#\r\n" + issue_title + "\r\n\r\n"

                # Appending the entirety of the current issue into a string variable
                if key == 'text':
                    issueText = self.stripTrash(str(issue[key]))
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
                        sanitizedFormattedValue = "#[{0}]#\r\n{1}\r\n\r\n".format(cey, self.stripTrash(str(fields[cey])))
                        if cey != 'Touched_By':
                            sanitizedFields.append(sanitizedFormattedValue)
                        else:
                            sanitizedFields.append("#[{0}]#\r\nJanitor_Bot_{1}\r\n\r\n".format(cey, today))

            sanitizedIssueText = ''.join(str(listEntry) for listEntry in sanitizedFields)

            # This is the only way to do PUT or POST requests with Dradis API
            data = {'issue': {"text": sanitizedIssueText}}
            issueUpdate = self.dradisSession.update_issue_raw(pid=projectId, issue_id=issueId, data=data)
        return

    def processArguments(self):
        # parse the arguments
        parser = ArgumentParser(epilog='\tExample: \r\npython ' + argv[0] +
                                       "https://dradis-pro.dev 21 xa632ghas87d393287",
                                description="Remove bad XML characters from Dradis issues")
        parser.add_argument('dradisUrl', help="Dradis URL")
        parser.add_argument('dradisProjectId', help="Dradis Project ID")
        parser.add_argument('dradisApiToken', help="Dradis API token")
        return parser.parse_args()

if __name__ == "__main__":
    start_time = time.time()
    scriptInstance = IssueJanitorScript()
    scriptInstance.run()
    print("\n\n%s seconds" % (time.time() - start_time))
