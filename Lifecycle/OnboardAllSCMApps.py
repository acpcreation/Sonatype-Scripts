#!/usr/bin/env python
import json
import requests
import time

# PRE REQUISITES:
# - Python 3
# - Make sure you configure your SCM in the IQ Organization you want the repos imported into: https://help.sonatype.com/iqserver/integrations/nexus-iq-for-scm/source-control-configuration-overview 
# - Ensure your source control personal access token has all the required permissions: https://help.sonatype.com/iqserver/integrations/nexus-iq-for-scm/source-control-configuration-overview

# ====== Environment variables ======
iqUrl = "http://localhost:8070/" #URL including trailing '/'
iqUsername = "admin" # Username for Sonatype IQ Server
iqPassword = "admin123" # Password for Sonatype IQ Server
iqOrganizationID = "" # Orgs & Policies > Choose the organization you want > Actions > Copy Org ID to Clipboard
selectedSCM = "azure" # Values (currently only 1): azure
getSCMProjectsURL = "" # Source Control API URL
scmUsername = "" # Source Control Username
scmAuthToken = "" # Source Control Access Token (Needs Permissions: https://help.sonatype.com/iqserver/integrations/nexus-iq-for-scm/source-control-configuration-overview)

throttleValue = 5 # Time delay in seconds between onboarding apps to prevent crashing
sonatypeAppOwner = "Admin" # Username of IQ application owner
sonatypeAppNamePrefix = "" # (Optional) Prefix for Application Names in IQ Server (Helps to prevent errors due to name conflicts)
#====================================


errorCount = 0
errorLogs = ""
repoImportCount = 0

########## Get All Repositories from Source Control ##########
scmList = []
def getSCMRepos():
    jsonData = None
    try:
        # Get list of repositories
        res = requests.get(getSCMProjectsURL, auth=(scmUsername, scmAuthToken)) #, timeout=120
        # Load result string to json
        jsonData = json.loads(res.text)
     
    except requests.exceptions.RequestException as e: 
        print("\nERROR: ")
        print(e)
        raise SystemExit(e)
    
    # Azure SCM
    if selectedSCM == "azure":
        # Azure docs: https://learn.microsoft.com/en-us/rest/api/azure/devops/git/repositories/list?view=azure-devops-rest-7.1&tabs=HTTP
        scmList = jsonData["value"]
        for i in range(len(scmList)):
            scmList[i]["url"] =  scmList[i]["webUrl"]

        print("Found "+str(jsonData["count"])+" repositories in "+selectedSCM)

    # elif OTHER SCM
    
    # Error
    else:
        print("\nOOPS! Looks like we don't support that source control yet, add a parser above to onboard the repositories.")
        quit()


    print("Onboarding SCM applications onto Sonatype Lifecycle, this might take a minute.")
    print("To prevent your Sonatype IQ Server from crashing we are going to throttle onboarding a bit.\n")
    global repoImportCount
    repoImportCount = len(scmList)
    for i in scmList:
        createIQApp(i)
        time.sleep(throttleValue) # Seconds
    

########## Create Application in IQ ##########
def createIQApp(scm):
    # Create new app in organization with associated SCM and trigger scan
    print("Importing "+scm["name"]+"...")
    jsonData = None

    url = iqUrl+"api/v2/applications/" 
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = json.dumps({
        "publicId": sonatypeAppNamePrefix+scm["name"],
        "name": sonatypeAppNamePrefix+scm["name"],
        "organizationId": iqOrganizationID,
        "contactUserName": sonatypeAppOwner,
    })
    
    try:
        res = requests.post( 
            url,
            auth=(iqUsername, iqPassword), 
            headers=headers,
            data=payload)
        
        jsonData = json.loads(res.text)
        # print(jsonData)
        print("\tSuccessfully created "+jsonData["name"]+" with internal ID: "+jsonData["id"])
    except:
        errMessage = "\nERROR: IQ applicaiton could not be created for "+selectedSCM+" source control: "+scm["url"]
        print(errMessage)
        print(res.text)
        logError(errMessage +" : "+ res.text)
        jsonData = None

    if jsonData != None:
        associateIQSCM({
            "url":scm["url"],
            "appID":jsonData["id"],
            "appName":jsonData["name"]
        })

        triggerSCMScan({
            "appId": jsonData["id"], 
            "appName": jsonData["name"] 
        })


########## Associate IQ Application with Source Control URL ##########
def associateIQSCM(scm):
    # https://help.sonatype.com/iqserver/automating/rest-apis/source-control-rest-api---v2

    url = iqUrl+"api/v2/sourceControl/application/"+ scm["appID"]
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    payload = json.dumps({
        # "token": "{scm access token}",
        "provider": selectedSCM,
        "repositoryUrl": scm["url"]
        # "baseBranch": "master",
        # "remediationPullRequestsEnabled": False,
        # "pullRequestCommentingEnabled": False,
        # "sourceControlEvaluationsEnabled": False
    })

    try:
        res = requests.post( 
            url,
            auth=(iqUsername, iqPassword), 
            headers=headers,
            data=payload)
        jsonData = json.loads(res.text)
        # print(jsonData)
        print("\tSuccessfully associated "+selectedSCM+" to IQ application "+scm["appName"]+" with url: \n\t\t"+scm["url"])

    except:
        errMessage = "\nERROR: Error associating source control to "+scm["appName"]+"("+scm["appID"]+") to source control with url: "+scm["url"]
        print(errMessage)
        print(res.text)
        logError(errMessage + " : "+ res.text)
        


########## Trigger IQ SCM Evaluation ##########
def triggerSCMScan(iqApp):
    # https://help.sonatype.com/iqserver/automating/rest-apis/source-control-evaluation-rest-api---v2
    url = iqUrl+"api/v2/evaluation/applications/"+iqApp["appId"]+"/sourceControlEvaluation" 
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = json.dumps({
        "stageId": "source",
        # "branchName": iqApp["branch"],
        "scanTargets": ["/"]
    })

    try:
        res = requests.post( 
            url,
            auth=(iqUsername, iqPassword), 
            headers=headers,
            data=payload)
        print("\tSuccessfully Triggered SCM Evalution for "+iqApp["appName"])
    
    except requests.exceptions.RequestException as e: 
        errMessage = "ERROR Triggering SCM Evaluation: "
        print(errMessage)
        print(e)
        logError(errMessage + " : "+e)


########## Trigger IQ SCM Evaluation ##########
def logError(e):
    global errorLogs,errorCount 
    errorLogs += e+" \n"
    errorCount += 1


#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    print("Onboarding All SCM Repositories for "+selectedSCM.upper()+"...")
    getSCMRepos()

    if errorLogs != "":
        dateTime = time.ctime(time.time())
        fileName = "errors-onboarding-SCM-"+dateTime+".log"
        f = open(fileName, "w")
        f.write(errorLogs)
        f.close()
        print("\n!! ERRORS WRITTEN TO: "+fileName+" !!")

    print("\nComplete! "+str(repoImportCount)+" source control repositories onboarded with "+str(errorCount)+" errors.")

    


