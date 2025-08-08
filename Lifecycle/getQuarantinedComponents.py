#!/usr/bin/env python
import json
import requests
from datetime import date

# ====== README ======
# This script gets the list of all the components currently in quarantine.
# The output is a CSV file containing the component, quarantine date, repository, number of policy violations, and link to the component.
#
# UPDATE THE VARIABLES BELOW
# NOTE: THIS IS A SONATYPE-COMMUNITY SCRIPT AND *NOT* SUPPORTED BY SONATYPE 
#

# ====== Environment variables ======
url = "http://localhost:8070/" #URL including trailing '/'
username = "admin"
password = "admin123"
#====================================


theurl = "%sapi/v2/firewall/components/quarantined" % (url)
global quarantineList


def getQuarantinedComponents():
    # fetch report from uri
    res = requests.get(theurl, auth=(username, password)) #, timeout=120
    
    json_data=[]
    try:
        # Load result string to json
        json_data = json.loads(res.text)
        # print(json_data) #All application
        print("Found "+str(json_data['total'])+" components...")
        global quarantineList
        quarantineList="Component, Quarantine Date, Repository, Violations Count, Link"
        for i in json_data['results']:
            if i["dateCleared"] == None:
                # print(i)
                quarantineList+= "\n"+i["displayName"]+","
                quarantineList+=i["quarantineDate"]+","
                quarantineList+=i["repository"]+","
                quarantineList+=str(len(i["quarantinePolicyViolations"]))+","
                quarantineList+=createComponentURL(i)
            
                # quarantineList.append({
                #     "component":i["displayName"],
                #     "quarantineDate":i["quarantineDate"],
                #     "repository":i["repository"],
                #     "violationsCount":len(i["quarantinePolicyViolations"]),
                #     "link": createComponentURL()
                # })  
            else:
                print("\t"+i["displayName"] +" omitted because it was cleared on "+i["dateCleared"])

    except Exception as err:
        print("\n=================")
        print("ERROR:")
        print(res.text)
        print()
        print(err)
        print()
        print("================= \n")
        quit()


def createComponentURL(e):
    componentURL = url+"assets/index.html#/firewall/repository/"
    componentURL+= e["repositoryId"]+"/component/"
    componentURL+=str(e["componentIdentifier"]).replace(" ", "").replace("\'", "\"").replace(",", "%2C") 
    componentURL+="/"+e["hash"]+"/"
    print("\t -"+componentURL)
    return componentURL


#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    print("Running...")
    getQuarantinedComponents()

    today = date.today()
    t = today.strftime("%b-%d-%Y") #today.strftime("%d/%m/%Y")
    f = open("FW-Quarantine-Report-"+t+".csv", "w")
    f.write(quarantineList)
    f.close()
    print("Done! Results written to FW-Quarantine-Report-"+t+".csv !")

# NOTE: THIS IS A SONATYPE-COMMUNITY SCRIPT AND *NOT* SUPPORTED BY SONATYPE 
