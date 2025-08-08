#!/usr/bin/env python
import json

def readPayload():
    fileName = "webhookPayload.json"
    print("Reading "+fileName)
    f = open(fileName)
    return json.load(f)

def writeToFile(e):
    f = open("uniqueIssues.json", "w")
    f.write(json.dumps(e))
    f.close()

# main
if __name__ == "__main__":
    print("Starting parse unique issues...")
    payload = readPayload()    
    print("Found "+str(len(payload["policyAlerts"]))+ " total issues")

    uniqueItems = []
    for i in payload["policyAlerts"]:
        for j in i["componentFacts"]:
            constraintReasons = []
            for k in j["constraintFacts"]:
                for l in k["satisfiedConditions"]:
                    constraintReasons.append(l["reason"])

            issue = {
                "component": j["displayName"],
                "highestViolation": i["policyName"],
                "violationSeverity": i["threatLevel"],
                "reasons": constraintReasons
            }

            issueFound = False
            for k in uniqueItems:
                if k["component"] == issue["component"]:
                    issueFound = True
                    k["reasons"] += issue["reasons"]
                    k["reasons"] = list(set(k["reasons"]))
                    if issue["violationSeverity"] > k["violationSeverity"]:
                       k["violationSeverity"] = issue["violationSeverity"]
                       k["highestViolation"] = issue["highestViolation"]         

            if issueFound == False:
                uniqueItems.append(issue)

    for i in uniqueItems:
        i["reasons"] = '\n'.join(i["reasons"])

    writeToFile(uniqueItems)

    print("Done! "+str(len(uniqueItems))+" unique issues found.")
