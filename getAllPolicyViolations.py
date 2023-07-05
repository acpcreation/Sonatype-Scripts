#!/usr/bin/env python
import json
# import csv
import requests
from datetime import date
# import asyncio


# ====== Environment variables ======
url = "http://localhost:8070/" #URL including trailing '/'
username = "admin"
password = "admin!23"
policyViolationMinimumThreat = 9.5 # Minimum policy threat level to include
#====================================

# iqApplications = ["WebGoat"] # "*" == All, or provide app ID
# iqStages = ["*"] # "*" == All, stages to include
allPolicyData = []
theurl = "%sapi/v2/applications/" % (url)

# Get global policy violations https://help.sonatype.com/iqserver/automating/rest-apis/policy-violation-rest-api---v2
def getIQPolicyViolations():
    print("\nGetting global policy violations above level "+str(policyViolationMinimumThreat))
    # Get all policies
    policyURL = url+ "api/v2/policies"
    policyList = requests.get(policyURL, auth=(username, password))
    # print(policyList.text)
    if "Invalid" not in policyList.text:  
        policyList = json.loads(policyList.text)
        # print(policyList)

        # Get policies violations by threat level
        for policy in policyList["policies"]:
            if policy["threatLevel"] >= policyViolationMinimumThreat:
                print("\tPolicy violaitons for "+policy["name"])
                policyIDURL = url+ "api/v2/policyViolations?p="+policy["id"]
                policyViolations = requests.get(policyIDURL, auth=(username, password))
                policyViolations = json.loads(policyViolations.text)
                allPolicyData.append(policyViolations)
                # print(policyViolations)
    else:
         print("ERROR: "+policyList.text)
    


#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    print("Running...")
    getIQPolicyViolations()

    today = date.today()
    t = today.strftime("%b-%d-%Y") #today.strftime("%d/%m/%Y")
    f = open("Sonatype-Policy-Violations-"+t+".json", "w")
    f.write(json.dumps(allPolicyData))
    f.close()

    print("\nDone writing to Sonatype-Policy-Violations-"+t+".json file!")
