#!/usr/bin/env python
import json
import csv
import math
import time
import settings

from googlesearch import search

# ========= ENVIRONMENT VARIABLES ========
# =============================================

#global competitorData
licenseData = []
violationsData = []
googleData = []
#enhancedData = []
competitorData = []


#Read both SBOMs
def import_reports():
    global licenseData, violationsData, competitorData
    licenseData = read_competitor_licenses()
    licenseData = consolidate_lic_components(licenseData)
    violationsData = read_competitor_violations()
    process_google_data()
    violationsData = consolidate_violation_components(violationsData)

    for i in licenseData:
        competitorData.append(i)

    for i in violationsData:
        competitorData.append(i)
        
    competitorData = consolidate_components(competitorData)


#Parse competitor data file
def read_competitor_licenses():
    print("Reading "+competitorLicenseExport+"... ")
    f = open(competitorLicenseExport, "r")

    licenseData = []

    #If file is .csv
    if competitorLicenseExport.endswith(".csv"):
        cols = {
            "identifier":None,
            "lic":None,
        }
        indexSet = False

        csvData = csv.reader(f)
        for lines in csvData:
            
            # Determine value columns
            if indexSet == False:
                cols = get_license_column_indicies(cols, lines)
                indexSet = True
            else:
                component = lines[cols["identifier"]]
                dataObj = {"component":component, "licenses":[], "cve":[]}
    
                if checkLicenses == True:
                    if(len(lines[cols["lic"]]) > 2):
                        dataObj["licenses"] = [lines[cols["lic"]]] #Check license length
    
                licenseData.append(dataObj)

    else:
        print("ERROR COMPETITOR SBOM ", competitorLicenseExport, " NOT COMPATIBLE!")
        quit()

    return licenseData


def get_license_column_indicies(cols, lines):
    print("\tFound column headers: ")
    for i in range(len(lines)):
        item = lines[i].lower()
        print("\t\t- <"+item+">")
        if item == "components id" or item == "component id":
            cols["identifier"] = i
        if item == "licenses" or item == "license":
            cols["lic"] = i

    for i in cols:
        if cols[i] == None:
            if (i == "lic" and checkLicenses == True) or i != "lic":
                colTitles = {
                    "identifier":"Identifiers",
                    "lic": "License",
                    "cve": "CVE",
                    "sev": "Severity"
                }
                print("\nERROR: Could not identify column header: **"+colTitles[i]+"**")
                print("Please make sure columns exist and are correctly labeled with Component, License, or CVEs. \n")
                quit()
    return cols


#Parse competitor data file
def read_competitor_violations():
    print("Reading "+competitorViolationsExport+"... ")
    f = open(competitorViolationsExport, "r")

    print("Reading "+enhancedDataFile+"... ")
    jFile = open(enhancedDataFile, "r")
    enhancedData = json.load(jFile)
    descriptions = enhancedData["Descriptions"]

    violationData = []

    #If file is .csv
    if competitorViolationsExport.endswith(".csv"):
        cols = {
            "identifier":None,
            "summary":None,
            "watch":None
        }
        indexSet = False
        
        csvData = csv.reader(f)
        for lines in csvData:
            
            # Determine value columns
            if indexSet == False:
                cols = get_violation_column_indicies(cols, lines)
                indexSet = True
            else:
                watch = lines[cols["watch"]]
                if watch.find("everything", 0) == -1:
                    continue
                    
                precomponent = lines[cols["identifier"]]
                parts = precomponent.split("//")
                if precomponent.startswith("npm://"):
                    component = parts[1]
                if precomponent.startswith("gav://"):
                    component = parts[1]
                
                dataObj = {"component":component, "licenses":[], "cve":[]}
                googleObj = {"summary":"", "cve":""}
    
                if(len(lines[cols["summary"]]) > 3):
                    summary=lines[cols["summary"]]
                    
                    found = False

                    for i in descriptions:
                        description = i["description"]
                        if found == False and description == summary:
#                            print("Match found: Component=" + component + "; " + description)
                            dataObj["cve"] = [i["cve"]]
                            found = True
                            break
                            
                    if not found:
                        dataObj["cve"] = [summary]
                        googleObj["summary"] = summary
                        if not googleObj in googleData:
                            googleData.append(googleObj)

                violationData.append(dataObj)

    else:
        print("ERROR COMPETITOR SBOM ", competitorViolationsExport, " NOT COMPATIBLE!")
        quit()

    return violationData


#Parse competitor data file
def process_google_data():
    cveCount = 0
    for lines in googleData:
        summary=lines["summary"]

        if summary.find(',') > 0:
            continue
#            summaryTxt = summary[0:summary.find(",")]
        else:
            print("Sleep for 3 seconds - to not swamp Google API")
            time.sleep(3)
            cveTxt = ""
            summaryTxt = summary

        if cveCount >= 0:
            for j in search(summaryTxt, tld="co.in", num=10, stop=10, pause=5):
                print ("Google returned: " +  j)
                foundStr = j.upper()
                if "/CVE-" in  foundStr:
                    print ("Usable: " +  j)
                    cveCount = cveCount + 1
                    cveStr = foundStr[foundStr.find("CVE-"):]
                    if cveStr.count("CVE-") > 1:
                        cveStr = cveStr[0:cveStr.find("/")]
                    cveStr = cveStr.replace(".HTML", "")
#                    if cveStr.find("16775") > 0:
#                        print("stop here")
                    if cveStr.find("/") > 0:
                        cveStr = cveStr[0:cveStr.find("/")]
                    
                    cveStr = cveStr.replace("/","")
                    if len(cveTxt) == 0:
                        cveTxt = cveStr
                    else:
                        if not cveStr in cveTxt:
                            cveTxt = cveTxt + " : " + cveStr
                            print("Add: " + cveStr)
                        else:
                            print("Duplicate: " + cveTxt + "; " + cveStr)
                             
#        if len(cveTxt) ==0:
#            cveTxt = summary

        lines["cve"] = cveTxt

    print ("Processed " + str(len(googleData)) + " GoogleData entries. Found " + str(cveCount) + " CVEs")
    
    for violation in violationsData:
        for googleLine in googleData:
            if googleLine["cve"] == "":
                continue
            if violation["cve"][0].find(googleLine["summary"]) == 0:
                violation["cve"] = [googleLine["cve"]]
                                    
    print("Finished processing GoogleData")


def get_violation_column_indicies(cols, lines):
    print("\tFound column headers: ")
    for i in range(len(lines)):
        item = lines[i].lower()
        print("\t\t- <"+item+">")
        if item == "components" or item == "component":
            cols["identifier"] = i
        if item == "summary":
            cols["summary"] = i
        if item == "watch-name":
            cols["watch"] = i
 
    return cols


#Sort unique components
def consolidate_lic_components(e):
    unique = []

    for i in e:
        found = False
        for j in range(len(unique)):
            if i["component"] == unique[j]["component"]:
                found = True

                for lic in i["licenses"]:
                    if lic not in unique[j]["licenses"]:
                        unique[j]["licenses"].append(lic)

        if found == False:
            unique.append(i)

    #Clean up data
    for i in unique:
        #Remove blank CVEs
        if i["cve"] == [""]:
            i["cve"] = []

    print("\t Found ",len(unique), " unique licensed components")
    return unique


#Sort unique components
def consolidate_violation_components(e):
    unique = []

    for i in e:
        found = False
#        if i["component"] == "lodash:2.4.2":
#            print("found first lodash:2.4.2")

        for j in range(len(unique)):
#            if i["component"] == "lodash:2.4.2" and unique[j]["component"] == "lodash:2.4.2":
#                print("found lodash:2.4.2")

            if i["component"] == unique[j]["component"]:
                found = True

                for lic in i["cve"]:
                    if lic not in unique[j]["cve"]:
                        unique[j]["cve"].append(lic)

        if found == False:
            unique.append(i)

    #Clean up data
    for i in unique:
        #Remove blank CVEs
        if i["cve"] == [""]:
            i["cve"] = []

    print("\t Found ",len(unique), " unique violations")
    return unique


#Sort unique components
def consolidate_components(e):
    unique = []

    print("length of incoming:" + str(len(e)))

    for i in e:
        found = False
        for j in range(len(unique)):
#            if i["component"] == "lodash:2.4.2" and unique[j]["component"] == "lodash:2.4.2":
#                print("found lodash:2.4.2")

            if i["component"] == unique[j]["component"]:
                found = True

                unique[j]["cve"] = i["cve"]

        if found == False:
            unique.append(i)

    #Clean up data
    for i in unique:
        #Remove blank CVEs
        if i["cve"] == [""]:
            i["cve"] = []

    print("\t Found ",len(unique), " unique components")
    return unique


def format_csv_report():
    # Write to CSV file
    csvReport = []
    header = []

    header = [
        "component",
        "licenses",
        "cve"]

    for i in competitorData:
        if len(header) > 0:
            component = str(i["component"])

            csvReport.append([
                i["component"],
                "; ".join(str(x) for x in i["licenses"]),
                "; ".join(str(y) for y in i["cve"])
            ])
        else:
            print("Define header")


    #Sort by match confidence and then name    
#    csvReport.sort(key=lambda row: (-1*int(row[2] or 0), row[3], row[0]), reverse=False)
    csvReport[:0] = [header]

    with open(outputFile,"w+") as my_csv:
        csvWriter = csv.writer(my_csv,delimiter=',')
        csvWriter.writerows(csvReport)

    print("CSV report written to '" + outputFile + "'...")


#==========================
#========== MAIN ==========
#==========================

def main():
    print("\n- INITIATING JFROG PARSING - ")
    global competitorLicenseExport, competitorViolationsExport, enhancedDataFile, outputFile, checkLicenses
    competitorLicenseExport = "input/" + settings.compShort + "/" + settings.compShort + "-" + settings.appShort + "-license-export.csv" # In the input folder
    competitorViolationsExport = "input/" + settings.compShort + "/" + settings.compShort + "-" + settings.appShort + "-violations-export.csv" # In the input folder
    enhancedDataFile = "output/sonatype/enhancedData-" + settings.appShort + ".json" # In the output directory
    outputFile = "processedFiles/" + settings.compShort + "/dependency-check-report-processed-" + settings.appShort + "-" + settings.compShort + ".csv"
    checkLicenses = True #Do a license comparison?

    import_reports()

    print("\nResults written to '" + outputFile + "'...")
    
    format_csv_report() #Print report in CSV format
