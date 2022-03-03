#!/usr/bin/env python
import json
import requests


# EDIT ENVIRONMENT VARIABLES
applicationID = "Struts2-rce"
url = "http://localhost:8070/" #URL including trailing '/'
username = "admin"
password = "admin!23"
stage = "*" # *, develop, source, build, stage-release, release 
#Configure the functions in the Main to determine what data to get



# =============================================
# =============================================
#Default variables
url = url+"api/v2/" #Update base url
fullReportData = []


def get_report_data():
    print("Getting ",applicationID," Reports...")
    # ref: https://help.sonatype.com/iqserver/automating/rest-apis/application-rest-apis---v2

    # fetch report from uri
    sendurl = url+"applications?publicId="+applicationID
    res = requests.get(sendurl, auth=(username, password)) #, timeout=120
    # Load result string to json
    json_data = json.loads(res.text) #Get internal app ID for input
    
    global internalAppID
    internalAppID = json_data['applications'][0]['id'] #Select first internal app ID
    sendurl = url+"reports/applications/"+internalAppID
    res = requests.get(sendurl, auth=(username, password))
    json_data = json.loads(res.text)
    # print(json_data) #Info for latest reports for each stage


    #Loop all reports 
    for item in json_data:
        if stage == "*" or item['stage'] == stage: #Only select desired stage(s)
            reportID = item['reportDataUrl'] 
            reportID = reportID.replace('api/v2/', '')
            # print(reportID)
            sendurl = url+reportID
            res = requests.get(sendurl, auth=(username, password))
            json_data = json.loads(res.text)
            json_data = json_data['components']
            newComponents = clean_duplicate_components(json_data)
            fullReportData.extend(newComponents)
    
    # print(fullReportData)
    

def clean_duplicate_components(newItems):
    print("Clean duplicate components...")
    returnList = []
    for i in newItems:
        found = False
        for j in fullReportData:
            if i['hash'] == j['hash']:
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
                    sendurl = url+"vulnerabilities/"+cve
                    res = requests.get(sendurl, auth=(username, password))
                    json_data = json.loads(res.text)
                    # print(json_data)
                    fullReportData[i]["securityData"]["securityIssues"][j]['deeperData'] = json_data
    print("Completed getting deeper vulnerability data")


# def get_policy_data():
    # ref: https://help.sonatype.com/iqserver/automating/rest-apis/policy-violation-rest-api---v2
    # print("Getting Policy Violation Data...")

    
#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    get_report_data() #Get SBOM data

    # [CONFIG]: GET VERSION FIX INFORMATION
    get_version_remediation_data() 

    # [CONFIG]: GET ALL CVE DETAIL DATA
    get_CVE_details()

    # [CONFIG]: GET POLICY DETAILS
    # get_policy_data() #TBD


    #Write to file
    f = open("fullReportData.json", "w")
    f.write(json.dumps(fullReportData))
    f.close()
    print("Results written to \'fullReportData.json\'")
