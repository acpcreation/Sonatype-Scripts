#!/usr/bin/env python
import json
import requests

# 
# READ ME:
# If you have scanned a number of applications with you IQ CLI or CI/CD integrations and 
# have not yet onboarded your applications via SCM, this script will automatically trigger 
# an SCM evaluation for any available source control configurations which have already been
# set. Make sure any apps you want to evaluate have appropriate authorization and source 
# control URLs set.
#

# ====== Environment variables ======
url = "http://localhost:8070/" #URL including trailing '/'
username = "admin"
password = "admin!23"
#====================================

url += "api/v2/"

def get_all_applications():
    # fetch report from uri
    sendURL = url+"applications/"
    # print(sendURL)
    res = requests.get(sendURL, auth=(username, password)) #, timeout=120
    
    json_data=[]
    try:
        # Load result string to json
        json_data = json.loads(res.text)
        # print(json_data) #All applications
        print("Found "+str(len(json_data['applications']))+" applications.")
        
    except:
        print("\n=================")
        print("ERROR: "+res.text)
        print("================= \n")
        quit()

    trigger_scm_oboarding(json_data['applications'])



def trigger_scm_oboarding(e):
    print("SCM Evaluation Complete for: ")
    noSCM = []
    scmCount = 0
    for i in e:
        # print(i["id"]+"\t - \t"+i["publicId"])

        sendURL = url+"evaluation/applications/"+i["id"]+"/sourceControlEvaluation"

        payload = json.dumps({
            "stageId": "source",
            # "branchName": "main"
        })
        headers = {
            'Content-Type': 'application/json',
        }

        response = requests.request("POST", sendURL, headers=headers, auth=(username, password), data=payload)
        # print(response.text)

        if str(response) == "<Response [200]>":
            print("\t- "+i["publicId"])
            scmCount += 1
        else:
            noSCM.append(i["publicId"])

    print(str(scmCount)+" source control evaluations triggered.")

    print("\nNo SCM found for ("+str(len(noSCM))+"):")
    for j in noSCM:
        print("\t- "+j)



#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    print("Triggering SCM onboarding for all available applications...")
    get_all_applications()
    
