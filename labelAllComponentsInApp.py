#!/usr/bin/env python
import json
import requests


# ====== PRE-REQUISITES ======
# In order for this script to succeed you will need to go to the 
# Orgs & Policies and create a new label at the ROOT level, name 
# it and then update the "labelName" field below to match.
#
# One you create the Label you can add a policy constraint on matching
# the label to apply policies in the desired fashion.
#

# ====== EDIT ENVIRONMENT VARIABLES ======
applicationID = "APP NAME"
url = "http://localhost:8070/" #URL including trailing '/'
username = "admin"
password = "admin!23"
stage = "build" #develop, source, build, stage-release, release
labelName = "Angular-Component" 
iqOrganization = "ROOT_ORGANIZATION_ID"


# =======================================================
# =======================================================
#Default variables
url = url+"api/v2/" 
componentList = []

#Get report data
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
    appFound = False
    for item in json_data:
        if item['stage'] == stage: #Only select desired stage(s)
            appFound = True
            print("Application \'"+stage+"\' Report Found...")
            reportID = item['reportDataUrl'] 
            reportID = reportID.replace('api/v2/', '')
            # print(reportID)
            sendurl = url+reportID
            res = requests.get(sendurl, auth=(username, password))
            json_data = json.loads(res.text)
            componentList.extend(json_data['components'])
    # print(componentList)
    
    if appFound == False:
        print("!! Application \'"+stage+"\' Report NOT Found !!")
    else:
        print(str(len(componentList))+" Components Found...")
        assign_component_labels()

def assign_component_labels():
    print("Assigning Labels to Components....")
    #APIs: https://help.sonatype.com/iqserver/automating/rest-apis/component-labels-rest-api---v2
    for i in componentList:
        sendurl = url+"components/"+i['hash']+"/labels/"+labelName+"/organizations/"+iqOrganization #Organization based label
        # sendurl = url+"components/"+i['hash']+"/labels/"+labelName+"/applications/"+internalAppID #Application based label
        res = requests.post(sendurl, auth=(username, password), data={})
        json_data = json.loads(res) #res.text
        print("..."+ json_data)


#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    get_report_data() #Get SBOM data

    print(str(len(componentList)) +" Components have been labeled!")

