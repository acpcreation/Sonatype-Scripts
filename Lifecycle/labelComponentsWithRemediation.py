#!/usr/bin/env python
import json
import requests

###############################################################
# Steps for use:
#   1. Create a global "Security-Fixable" label in Lifecycle
#   2. Create or edit a policy with the "Security-Fixable" 
#      label as a policy constraint along with the CVE severity.
#   3. Update the Lifeycle variables below
#   4. All future scans will see this label applied to the relevant 
#      components. If you want to see the results immediately, go to
#      the reports and click "Re-Evaluate Report".        
###############################################################


# ========= ENVIRONMENT VARIABLES ========
applicationIDs = ["label-fixable"] 
iqURL = "http://localhost:8070/" #URL including trailing '/'
username = "admin"
password = "admin!23"
stage = "build" # *, develop, source, build, stage-release, release 
labelName = "Security-Fixable" #Create this label in IQ and create policy on it
#Configure the functions in the Main to determine what data to get

# =============================================



#Default variables
if iqURL[len(iqURL)-1] != "/":
    iqURL = iqURL+"/" #Append if no trailing "/"
url = iqURL+"api/v2/" #Update base url

fullReportData = []
cveList = []
fixableItems = []

def get_report_data():
    print("Getting ",str(applicationIDs)," Reports...")
    # ref: https://help.sonatype.com/iqserver/automating/rest-apis/application-rest-apis---v2

    

    # if "*" in applicationIDs:
    #     get_all_application

    for applicationID in applicationIDs:
        # Get internal ID
        sendurl = url+"applications?publicId="+applicationID
        res = requests.get(sendurl, auth=(username, password)) #, timeout=120
        json_data = json.loads(res.text) #Get internal app ID for input
        global internalAppID
        internalAppID = json_data['applications'][0]['id'] #Select first internal app ID

        # Get reports from internal IDs
        sendurl = url+"reports/applications/"+internalAppID
        res = requests.get(sendurl, auth=(username, password))
        json_data = json.loads(res.text)
        # print(json_data) #Info for latest reports for each stage
        iterate_and_aggregate_reports(json_data, applicationID)

def iterate_and_aggregate_reports(e, applicationID):
    #Loop all reports 
    for item in e:
        if stage == "*" or item['stage'] == stage: #Only select desired stage(s)
            reportID = item['reportDataUrl'] 
            reportID = reportID.replace('api/v2/', '')
            # print(reportID)
            sendurl = url+reportID
            res = requests.get(sendurl, auth=(username, password))
            e = json.loads(res.text)
            e = e['components']
            e = add_json_fields(e, applicationID, internalAppID)
            newComponents = clean_duplicate_components(e)
            fullReportData.extend(newComponents)
            
def add_json_fields(e, id, internalID):
    for i in range(len(e)):
        e[i]["applications"] = [id]
        e[i]["remediationPath"] = None
        e[i]["internalAppIDs"] = [internalID]

    return e


def clean_duplicate_components(newItems):
    print("Clean duplicate components...")
    returnList = []
    for i in newItems:
        found = False
        for j in range(len(fullReportData)):
            if i['hash'] == fullReportData[j]['hash']:
                fullReportData[j]['applications'].extend(i["applications"])
                fullReportData[j]['internalAppIDs'].extend(i["internalAppIDs"])
                found = True
        if found == False:
            returnList.append(i)

    return returnList

def get_version_remediation_data():
    print("Getting Remediation Data for ",len(fullReportData)," Components...")
    # ref: https://help.sonatype.com/iqserver/automating/rest-apis/component-remediation-rest-api---v2

    for i in range(len(fullReportData)):
        sendurl = url+"components/remediation/application/"+internalAppID
        if stage != "*":
            sendurl = sendurl +"?stageId="+stage
        
        print(fullReportData[i]["componentIdentifier"])
        payload = json.dumps({"componentIdentifier":fullReportData[i]["componentIdentifier"]})
        if payload == None:
            payload =  json.dumps({"packageUrl":fullReportData[i]["packageUrl"]}) #Sometimes returns None

        headers = {
            'Content-Type': 'application/json'
        }
        res = requests.post(
            sendurl, 
            auth=(username, password), 
            headers=headers,
            data=payload)
        try:
            json_data = json.loads(res.text)
            fullReportData[i]["remediation"] = json_data["remediation"]
        except:
            fullReportData[i]["remediation"] = res.text +" Usually this is a proprietary component."


def get_CVE_details():
    print("Getting CVE Data for ",len(fullReportData)," Components...")
    # ref: https://help.sonatype.com/iqserver/automating/rest-apis/vulnerability-details-rest-api---v2

    for i in range(len(fullReportData)):
        if fullReportData[i]["securityData"] != None:
            if len(fullReportData[i]["securityData"]["securityIssues"]) >0:
                for j in range(len(fullReportData[i]["securityData"]["securityIssues"])):
                    cve = fullReportData[i]["securityData"]["securityIssues"][j]['reference']
                    print(cve+'...')
                    
                    cveFound = False
                    for k in cveList:
                        if cve == k["cve"]:
                            cveFound = k
                            break
                    
                    if cveFound == False:
                        sendurl = url+"vulnerabilities/"+cve
                        res = requests.get(sendurl, auth=(username, password))
                        json_data=None
                        try:
                            json_data = json.loads(res.text)
                            # print(json_data)
                        except:
                            json_data = res.text
                    
                        fullReportData[i]["securityData"]["securityIssues"][j]['deeperData'] = json_data
                        cveList.append({
                            "cve":cve,
                            "data":json_data
                        })
                    else:
                        # print("Quick find")
                        fullReportData[i]["securityData"]["securityIssues"][j]['deeperData'] = cveFound["data"]
    print("Completed getting deeper vulnerability data...")



def get_version_remediations():
    print("Getting fixable items...")
    for i in range(len(fullReportData)):
        try:
            if len(fullReportData[i]["remediation"]["versionChanges"]):
                fullReportData[i]["remediationPath"] = "Version"
        except:
            pass


def get_workarounds():
    for i in range(len(fullReportData)):
        try:
            for j in fullReportData[i]["securityData"]["securityIssues"]:
                # cve = j["reference"]
                workaround = j["deeperData"]["recommendationMarkdown"]
                if "workaround" in workaround or "configur" in workaround or "is not a" in workaround :
                    # workaround = workaround.replace("We recommend upgrading to a version of this component that is not vulnerable to this specific issue.\n", "")
                    # cveList.append({"cve":cve, "remediation":workaround})
                    if fullReportData[i]["remediationPath"] == None:
                        fullReportData[i]["remediationPath"] = "Workaround"
                    else:
                        fullReportData[i]["remediationPath"] += " and Workaround"
        except:
            pass
    

def format_output():
    for i in fullReportData:
        if i["remediationPath"] != None:
            fixableItems.append(i)
            # fixableItems.append({
            #     "displayName": i["displayName"],
            #     "hash": i["hash"],
            #     "securityData": i["securityData"],
            #     "applications": i["applications"],
            #     "remediationPath": i["remediationPath"],
            #     "remediation": i["remediation"]
            # })

    print("\n"+str(len(fixableItems))+" items found with remediation path!")


def label_components():
    print("Labeling fixable components...")
    # https://help.sonatype.com/iqserver/automating/rest-apis/component-labels-rest-api---v2
    # f = open("fixable-items.json", "r")
    # fixableItems = json.load(f)

    for i in fixableItems:
        for j in i["internalAppIDs"]:
            sendurl = url+"components/"+i["hash"]+"/labels/"+labelName+"/applications/"+j
            res = requests.post(sendurl, auth=(username, password)) 
            # json_data = json.loads(res.text)

    #Trigger continuous monitoring for all apps
    print("Reevaluating report with new labels in place...")
    z = len(iqURL)-2
    newURL = iqURL[:z] + "1" + iqURL[z + 1:]
    sendurl = newURL+"tasks/triggerPolicyMonitor"
    res = requests.post(sendurl, auth=(username, password)) 
    print(res.text)

    #Write to file
    file = "fixable-items.json"
    f = open(file, "w")
    f.write(json.dumps(fixableItems))
    f.close()
    print("Results written to \'"+file+"\'")
    


#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    get_report_data() #Get SBOM data

    # [CONFIG]: GET VERSION FIX INFORMATION
    get_version_remediation_data() 

    # [CONFIG]: GET ALL CVE DETAIL DATA
    get_CVE_details()

    get_version_remediations()
    get_workarounds()
    format_output()
    label_components()
