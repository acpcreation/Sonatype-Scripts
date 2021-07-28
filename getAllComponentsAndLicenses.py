#!/usr/bin/env python
import json
import requests
from datetime import date


# Environment variables
uri = "localhost"
port = str(8070)
username = "admin"
password = "admin!23"
allData = []

theurl = "http://%s:%s/api/v2/applications/" % (uri, port)


def scan_all_IQ_reports():
    # fetch report from uri
    res = requests.get(theurl, auth=(username, password))

    # Load result string to json
    json_data = json.loads(res.text)
    # print(json_data) #All application

    # iterate json
    for applications in json_data['applications']:
        app_id_hash = str(applications['id'])
        theurl2 = "http://%s:%s/api/v2/reports/applications/" % (uri, port) + str(app_id_hash)
        res2 = requests.get(theurl2, auth=(username, password))
        json_data_reps = json.loads(res2.text)
        # print(json_data_reps) #Get all reports


        # gets url for build stage of app / BOM
        for items in json_data_reps:
            reporturl = items['reportDataUrl']
            theurl3 = "http://%s:%s/" % (uri, port) + str(reporturl)
            res3 = requests.get(theurl3, auth=(username, password))
            json_data_comps = json.loads(res3.text)
            # print(json_data_comps['components'][0])

            for comps in json_data_comps['components']:
                if comps['componentIdentifier'] != None:
                    comps['applications'] = [applications['name']]
                    count_security_and_licence(comps)



def count_security_and_licence(comps):

    allLicenses = []
    licenseData = comps['licenseData']
    # Declared Licenses
    for i in licenseData["declaredLicenses"]:
        allLicenses.append(i["licenseName"])

    # Observed Licenses
    for i in licenseData["observedLicenses"]:
        allLicenses.append(i["licenseName"])
    
    # Effective Licenses
    for i in licenseData["effectiveLicenses"]:
        allLicenses.append(i["licenseName"])

    effectiveLicenseThreats = []
    for i in licenseData['effectiveLicenseThreats']:
        item = str(i['licenseThreatGroupName'])+" ("+str(i['licenseThreatGroupLevel'])+")"
        effectiveLicenseThreats.append(item)
    
    
    comps['allLicenses'] = list(dict.fromkeys(allLicenses))
    comps['effectiveLicenseThreats'] = list(dict.fromkeys(effectiveLicenseThreats))
        
    # Remove Irrelevant
    parametersToRemove = [  
        "packageUrl",
        "proprietary",
        "matchState",
        "pathnames",
        "dependencyData",
        "licenseData"
    ]
    for i in parametersToRemove:
        if i in comps:
            del comps[i]
    
    # Clean Security Data
    if len(comps['securityData']['securityIssues']) <1:
        comps['securityData'] = []
    else:
        securityRisks = []
        for i in comps['securityData']['securityIssues']:
            securityRisks.append(i['reference']+' ('+str(i['severity'])+')')
        comps['securityData'] = securityRisks


    #Clean up License Data
    for i in comps['allLicenses']:
        if i in 'Not Supported' or i in "No Source License":
           comps['allLicenses'].remove(i) 


    # If duplicates then merge
    found = False
    for i in range(len(allData)):
        if allData[i]['hash'] == comps ['hash']:
            found = True

            # Append Application(s)
            if comps['applications'][0] not in allData[i]['applications']:
                allData[i]['applications'].append(comps['applications'][0])

            # Append License(s)
            for j in comps['allLicenses']:
                if j not in allData[i]['allLicenses']:
                    allData[i]['allLicenses'].append(j)
            
            # Append License Threats
            for j in comps['effectiveLicenseThreats']:
                if j not in allData[i]['effectiveLicenseThreats']:
                    allData[i]['effectiveLicenseThreats'].append(j)

            # Append Security Data
            for j in comps['securityData']:
                if j not in allData[i]['securityData']:
                    allData[i]['securityData'].append(j)
            break

    # Append to array
    if found == False:
        allData.append(comps)
   

#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
 
    print("Running.. This will take a few minutes..")
    #main method
    scan_all_IQ_reports()

    today = date.today()
    t = today.strftime("%b-%d-%Y") #today.strftime("%d/%m/%Y")

    f = open("allDataReport-"+t+".json", "w")
    everything = {'all':allData}
    f.write(json.dumps(everything))
    f.close()   

    print("Done!")
    print("Report written to allDataReport.json")
    

    