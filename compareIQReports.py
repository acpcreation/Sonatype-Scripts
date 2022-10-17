#!/usr/bin/env python
import json
import requests
import csv

##########
# This script takes all the reports across each stage of any combination of applications
# and compares the results of the components to see which components were found in the
# various application stage reports.
#
# This will allow us to compare the results of the different stages of reports 
# for applications.
##########

# ========= ENVIRONMENT VARIABLES ========
applicationID = ["App1ID", "App2ID"] #List of apps to compare
url = "http://localhost:8070/" #URL including trailing '/'
username = "admin"
password = "admin!23"
stages = ["*"] # *, develop, source, build, stage-release, release 
# ^^^ Use this array to compare any specific desired stagesm ^^^
# =============================================


#Default variables
url = url+"api/v2/" #Update base url
allReports = []
outputData = []
headerRow = []


def get_report_data():
    print("Getting ",applicationID," Reports...")
    # ref: https://help.sonatype.com/iqserver/automating/rest-apis/application-rest-apis---v2

    for app in applicationID:
        # fetch report from uri
        sendurl = url+"applications?publicId="+app
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
            if "*" in stages or item['stage'] in stages: #Only select desired stage
                reportID = item['reportDataUrl'] 
                reportID = reportID.replace('api/v2/', '')
                # print(reportID)
                sendurl = url+reportID
                res = requests.get(sendurl, auth=(username, password))
                json_data = json.loads(res.text)

                allReports.append({
                    "stage":item['stage'], 
                    "components":json_data['components'],
                    "application": app
                })


#Compare components accross stages
def compare_stages():
    print("Comparing stage reports...")
    found = True

    #Compare the hashes
    for selectStage in allReports:
        for s in allReports:
            if selectStage["stage"] != s["stage"]:
                for i in selectStage["components"]:
                    
                    data={}
                    for r in allReports:
                        data[r["stage"]] = ""

                    data["component"] = i["displayName"]
                    data[selectStage["stage"]] = found

                    for j in s["components"]:
                        if i["hash"] == j["hash"]:
                            data[s["stage"]] = found

                    data["applications"] = selectStage["application"]

                    global outputData
                    outputData.append(data)

    #Header row
    global headerRow
    headerRow = ["component", "applications"]
    for i in allReports:
        headerRow.append(i["stage"])

    outputData = clean_duplicates(outputData)


#Clean up duplicates
def clean_duplicates(e):
    global headerRow
    unique = []
    while len(e) > 0:
        item = e[0]
        del e[0]

        i = 0
        while i < len(e):
            if item["component"] == e[i]["component"]:

                #Iterate through the headers and match the fields
                for j in headerRow:
                    if e[i][j] != "":
                        #Set if found
                        if type(e[i][j]) == bool:
                            item[j] = e[i][j]
                        
                        #Append apps
                        elif e[i][j] not in item[j]:
                            item[j] += " ; "+e[i][j]

                del e[i]
                i-=1
            
            #Iterate
            i+=1
            
        unique.append(item)

    print("Found ", len(unique)," components...")
    return unique


#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    get_report_data() #Get SBOM data
    compare_stages()

    print("Formatting CSV...")

    csvData = []
    for i in outputData:
        row = []
        for j in headerRow:
            row += [i[j]]

        csvData.append(row)

    #Write to CSV file
    with open("compare-iq-reports.csv","w+") as my_csv:
        csvWriter = csv.writer(my_csv,delimiter=',')
        csvWriter.writerow(headerRow)
        csvWriter.writerows(csvData)

    print("Results written to compare-iq-reports.csv")
