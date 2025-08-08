#!/usr/bin/env python
import json
import csv
import math
import settings

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
                identifier = lines[cols["identifier"]]
                bigpart = identifier.split(',')
 
                for i in range(len(bigpart)):
                    parts = bigpart[i].split('/')

                    if parts[0].find('pkg:javascript') >= 0:
#                        print('Starts with : ' + parts[0])
                        start = 'org.webjars'
                    else:
#                        print('Does not startswith : pkg:javascript ' + parts[0])
                        start = ""

                    if len(parts) == 3:
                        name = parts[2].replace("@", ":")
                        component = parts[1] + ":" + name
                    elif len(parts) == 2:
                        name = parts[1].replace("@", ":")
                        if parts[0].find('pkg:javascript') >= 0:
#                        print('Starts with : ' + parts[0])
                            component = 'org.webjars:' + name
                        else:
                            component = name

                    else:
                        component = "OOPS"
    
                    dataObj = {"component":component, "licenses":[], "cve":[]}
    
                    if checkLicenses == True:
                        if(len(lines[cols["lic"]]) > 3):
                            dataObj["licenses"] = [lines[cols["lic"]]] #Check license length
    
                    if(len(lines[cols["cve"]]) > 3):
                        if lines[cols["cve"]].startswith('CVE'): # only add CVE if string starts with CVE
#                            print('Starts with : CVE')
                            dataObj["cve"] = [lines[cols["cve"]]]
#                        else;
#                             print("OOPS")
    
                    returnData.append(dataObj)
                

    else:
        print("ERROR COMPETITOR SBOM ", competitorSBOM, " NOT COMPATIBLE!")
        quit()

    return returnData


def get_column_indicies(cols, lines):
    print("\tFound column headers: ")
    for i in range(len(lines)):
        item = lines[i].lower()
        print("\t\t- "+item)
        if "identifiers" == item or "identifier" == item:
            cols["identifier"] = i
        if "licenses" == item or "license" == item:
            cols["lic"] = i
        if "cves" == item or "cve" == item:
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
                for k in i["cve"]:
                    if k not in unique[j]["cve"]:
                        unique[j]["cve"].append(k)     

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
                ", ".join(str(x) for x in i["licenses"]),
                ", ".join(str(y) for y in i["cve"])
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
    print("\n- INITIATING OWASP PARSING - ")
    global competitorSBOM, outputFile, checkLicenses
    competitorSBOM = "input/" + settings.compShort + "/dependency-check-report-raw-" + settings.appShort + "-" + settings.compShort + ".csv"
    outputFile = "processedFiles/" + settings.compShort + "/dependency-check-report-processed-" + settings.appShort + "-" + settings.compShort + ".csv"
    checkLicenses = True

    import_reports()

    print("\nResults written to '" + outputFile + "'...")
    
    format_csv_report() #Print report in CSV format
