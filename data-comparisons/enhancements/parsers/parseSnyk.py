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
competitorData = []


#Read both SBOMs
def import_reports():
    global competitorData
    competitorData = read_competitor_sbom()
    competitorData = consolidate_components(competitorData)


#Parse competitor data file
def read_competitor_sbom():
    print("Reading "+competitorSBOM+"... ")
    f = open(competitorSBOM, "r")

    returnData = []

    #If file is .csv
    if competitorSBOM.endswith(".csv"):
        cols = {
            "identifier":None,
            "lic":None,
            "cve":None,
            "sev":"N/A"
        }
        indexSet = False
        
        csvData = csv.reader(f)
        for lines in csvData:
            
            # Determine value columns
            if indexSet == False:
                cols = get_column_indicies(cols, lines)
                indexSet = True
            else:
                component = lines[cols["identifier"]]
                dataObj = {"component":component, "licenses":[], "cve":[]}
    
                if checkLicenses == True:
                    licStr = lines[cols["lic"]]
                    if(len(licStr) > 3):
                        if licStr.find("license") > 0:
                            dataObj["licenses"] = [licStr]

                searchStr = lines[cols["cve"]]
                if len(searchStr) > 3:
                    if searchStr.startswith("snyk:lic:"):
                        dataObj["cve"] = []
                    else:
                        time.sleep(3)
                        cveTxt = ""
                        for j in search(searchStr, tld="co.in", num=10, stop=10, pause=5):
                            print ("Google returned: " +  j)
                            foundStr = j.upper()
                            if "/CVE-" in  foundStr:
                                print ("Usable: " +  j)
#                                cveCount = cveCount + 1
                                cveStr = foundStr[foundStr.find("CVE-"):]
                                cveStr = cveStr.replace("/","")
                                if len(cveTxt) == 0:
                                    cveTxt = cveStr
                                else:
                                    if not cveStr in cveTxt:
                                        cveTxt = cveTxt + " : " + cveStr
                                        print("Add: " + cveStr)
                                    else:
                                        print("Duplicate: " + cveTxt + "; " + cveStr)

                        if len(cveTxt) ==0:
                            print ("Not Usable: " +  searchStr)
                            cveTxt = searchStr
    
                        dataObj["cve"] = [cveTxt]

                returnData.append(dataObj)

    else:
        print("ERROR COMPETITOR SBOM ", competitorSBOM, " NOT COMPATIBLE!")
        quit()

    return returnData


def get_column_indicies(cols, lines):
    print("\tFound column headers: ")
    for i in range(len(lines)):
        item = lines[i].lower()
        print("\t\t- <"+item+">")
        if item == "components" or item == "component":
            cols["identifier"] = i
        if item == "issue.title":
            cols["lic"] = i
        if item == "issue.id":
            cols["cve"] = i
        # if "severity" == item:
        #     cols["sev"] = i

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


#Sort unique components
def consolidate_components(e):
    unique = []

    for i in e:
        found = False
        for j in range(len(unique)):
            if i["component"] in unique[j]["component"]:
                found = True
                for k in i["licenses"]:
                    if k not in unique[j]["licenses"]:
                        unique[j]["licenses"].append(k)     
                for l in i["cve"]:
                    if l not in unique[j]["cve"]:
                        unique[j]["cve"].append(l)     

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
    print("\n- INITIATING SNYK PARSING - ")
    global competitorSBOM, outputFile, checkLicenses
    competitorSBOM = "input/" + settings.compShort + "/" + settings.compShort + "-" + settings.appShort + "-error.csv" # In the input folder
    outputFile = "processedFiles/" + settings.compShort + "/dependency-check-report-processed-" + settings.appShort + "-" + settings.compShort + ".csv"
    checkLicenses = True #Do a license comparison?

    import_reports()

    print("\nResults written to '" + outputFile + "'...")
    
    format_csv_report() #Print report in CSV format


if __name__ == "__main__":
    main()
