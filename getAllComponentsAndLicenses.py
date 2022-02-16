#!/usr/bin/env python
import json
import csv
import requests
from datetime import date


# Environment variables
url = "http://localhost:8070/" #URL including trailing '/'
username = "admin"
password = "admin!23"
allData = []
csvReport = []

theurl = "%sapi/v2/applications/" % (url)


def scan_all_IQ_reports():
    # fetch report from uri
    res = requests.get(theurl, auth=(username, password)) #, timeout=120

    # Load result string to json
    json_data = json.loads(res.text)
    # print(json_data) #All application
    print("Found "+str(len(json_data['applications']))+" applications..")

    # iterate json
    for applications in json_data['applications']:
        app_id_hash = str(applications['id'])
        theurl2 = "%sapi/v2/reports/applications/" % (url) + str(app_id_hash)
        res2 = requests.get(theurl2, auth=(username, password))
        json_data_reps = json.loads(res2.text)
        # print(json_data_reps) #Get all reports

        # gets url for build stage of app / BOM
        for items in json_data_reps:
            reporturl = items['reportDataUrl']
            theurl3 = "%s" % (url) + str(reporturl)
            res3 = requests.get(theurl3, auth=(username, password))
            json_data_comps = json.loads(res3.text)
            # print(json_data_comps['components'][0])
            print("\t"+str(len(json_data_comps['components'])) +"\t components found for "+items['reportHtmlUrl'].replace('ui/links/application/', '') )

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


# Convert to CSV Method
def convert_to_csv():
    print("Converting to CSV...")
    #Iterate through full vulnerability report
    for i in range(len(allData)):
        d = allData[i]
        row = [d['displayName'].replace(',', '')] #d['hash'],  
        row += [d['applications']]
        row += [d['allLicenses']]
        row += [d['effectiveLicenseThreats']]
        csvReport.append(row)



#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
 
    print("Running.. This will take a few minutes..")
    scan_all_IQ_reports()
    today = date.today()
    t = today.strftime("%b-%d-%Y") #today.strftime("%d/%m/%Y")
    f = open("allDataReport-"+t+".json", "w")
    everything = {'all':allData}
    f.write(json.dumps(everything))
    f.close()
    print("Done generating report!")
    print("Data written to allDataReport.json")

    
    
    #CONVERT TO CSV
    #Open local report to convert to CSV
    # f = open('allDataReport.json')
    # allData = json.load(f)
    # allData = allData['all']

    convert_to_csv() #Convert to CSV

    #Write to CSV file
    with open("allDataCSVReport-"+t+".csv","w+") as my_csv:
        csvWriter = csv.writer(my_csv,delimiter=',')
        csvWriter.writerow(["Component","Applications","License(s)","License Threats"])
        print(csvReport[100])
        csvWriter.writerows(csvReport)

    print("Done writing to CSV... check the allDataCSVReport-"+t+".csv file for results.")
