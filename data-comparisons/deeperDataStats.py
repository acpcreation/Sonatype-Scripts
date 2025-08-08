#!/usr/bin/env python
import json
import requests


# ========= ENVIRONMENT VARIABLES ========
remediationDataFile = ""
enhancedDataFile = ""

# =============================================

jsonData = []

global enhancedData
enhancedData = {
    "TotalDescriptions": 0,
    "Descriptions":[],
    "TotalAdvisories": 0,
    "UniqueAdvisories":0,
    "Advisories":[],
    "TotalWorkarounds":0,
    "Workarounds":[],
    "DeepDiveResearch":0,
    "SonatypeCVECount":0,
    "TotalCVEs":0
}


def read_json_report():
    print("Reading ", remediationDataFile,"...")
    f = open(remediationDataFile, "r")
    global jsonData
    jsonData = json.load(f)
    f.close()
    get_deviation_advisories_and_workarounds()


def get_deviation_advisories_and_workarounds():
    descList = []
    cveList = []
    workaroundList = []
    for i in jsonData:
        try:
            for j in i["securityData"]["securityIssues"]:
                cve = j["reference"]

                if not cve.startswith("sonatype"):
                    description = j["deeperData"]["description"]
                    descList.append({"displayName":i["displayName"],"cve":cve, "description":description})
                    # print(cve)

                advisory = j["deeperData"]["explanationMarkdown"]
                if "Advisory Deviation Notice" in advisory:
                    cveList.append({"cve":cve, "advisory":advisory})

                workaround = j["deeperData"]["recommendationMarkdown"]
                if "workaround" in workaround or "configur" in workaround or "is not a" in workaround :
                    workaround = workaround.replace("We recommend upgrading to a version of this component that is not vulnerable to this specific issue.\n", "")
                    workaroundList.append({"cve":cve, "remediation":workaround})

                if "sonatype-" in cve:
                    enhancedData["SonatypeCVECount"] += 1 #sum(1 for k in j["deeperData"]["vulnIds"] if "SONATYPE" in k)
                
                if "DEEP_DIVE" in j["deeperData"]["researchType"]:
                    enhancedData["DeepDiveResearch"] += 1

                enhancedData["TotalCVEs"] += len(j["deeperData"]["vulnIds"])

        except:
            pass
            # print("No security data for ", i["displayName"])
    
    print("\nEnhanced data:")
    enhancedData["TotalDescriptions"] = len(descList)
    print("\t- Descriptions: ", len(descList))
    enhancedData["Descriptions"] = descList

    enhancedData["TotalAdvisories"] = len(cveList)
    cveList = {elem["cve"]:elem for elem in cveList}.values() 
    enhancedData["UniqueAdvisories"] = len(cveList)
    finalList=[]

    print("\t- Deviation Advisories: ", len(cveList))
    for i in cveList:
        # print("\t - ",i["cve"])
        finalList.append({"cve":i["cve"], "advisory":i["advisory"]})

    enhancedData["Advisories"] = finalList

    enhancedData["TotalWorkarounds"] = len(workaroundList)
    enhancedData["Workarounds"] = workaroundList
    print("\t- Workarounds: ", len(workaroundList))
    print("\t- Sonatype CVEs: ", enhancedData["SonatypeCVECount"])
    print("\t- Deep Dive Issues: ", enhancedData["DeepDiveResearch"])

def count_components_with_version_fix():
    print("FIX: Add number of components with version fixed that can be triggered by automation.")



#==========================
#========== MAIN ==========
#==========================
def main(e):
    #deeperDataStats
    print("\n- GENERATING DEEPER DATA STATS - ")

    global remediationDataFile, enhancedDataFile
    remediationDataFile = e["sonatypeSBOM"]
    enhancedDataFile = e["enhancedDataFile"]

    read_json_report()

    # Write to file
    f = open(enhancedDataFile, "w")
    f.write(json.dumps(enhancedData))
    f.close()
    print("Results written to '" + enhancedDataFile + "'...")
    