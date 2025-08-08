#!/usr/bin/env python
import json
import csv
import math
import settings

# ========= ENVIRONMENT VARIABLES ========
# =============================================

manifestData = []
cveData = []
competitorData = []


#Read both SBOMs
def import_reports():
    global manifestData, cveData, competitorData
    manifestData = read_competitor_manifest()
    manifestData = consolidate_manifest(manifestData)
    cveData = read_competitor_cve()
    cveData = consolidate_components(cveData)
    competitorData = mergeData ()


#Parse competitor data file
def read_competitor_manifest():
    print("Reading "+competitorManifestFile+"... ")
    f = open(competitorManifestFile, "r")

    returnData = []
       
    csvData = csv.reader(f)
    for name in csvData:
        parts = name[0].split("/")
        component = parts[len(parts) - 1]
        dataObj = {"component":component, "licenses":[], "cve":[]}
        returnData.append(dataObj)

    returnData = sorted(returnData, key=lambda item: item["component"])

    return returnData

#Parse competitor data file
def read_competitor_cve():
    print("Reading "+competitorCVEsFile+"... ")
    f = open(competitorCVEsFile, "r")

    returnData = []

    #If file is .csv
    if competitorCVEsFile.endswith(".csv"):
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
                name = lines[cols["identifier"]]
                parts = name.split("-")
                if len(parts) == 2:
                    component = parts[0] + ":" + parts[1]
                elif len(parts) == 3:
                    component = parts[0] + "-" + parts [1] + ":" + parts[2]
                else:
                    component = name

                dataObj = {"component":component, "licenses":[], "cve":[]}
    
    
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

    returnData = sorted(returnData, key=lambda item: item["component"])

    return returnData


def get_column_indicies(cols, lines):
    print("\tFound column headers: ")
    for i in range(len(lines)):
        item = lines[i].lower()
        print("\t\t- "+item)
        if "components" == item or "component" == item:
            cols["identifier"] = i
#        if "licenses" == item or "license" == item:
#            cols["lic"] = i
        if "cves" == item or "cve" == item:
            cols["cve"] = i
        # if "severity" == item:
        #     cols["sev"] = i

    return cols


#Sort unique components
def consolidate_manifest(e):
    unique = []

    for i in e:
        found = False
        for j in range(len(unique)):
            if i["component"] in unique[j]["component"]:
                found = True

        if found == False:
            unique.append(i)

    print("\t Found ",len(unique), " unique components")
    return unique


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

    print("\t Found ",len(unique), " unique CVE components")
    return unique


def mergeData():
    print("merging data")
    returnData = []
    for item in manifestData:
        name = item['component']
#        if name == "angular.min.js":
#            print("stop gere!!")
        for cve in cveData:
            cveName = cve['component']
            if name == cveName:
                item['cve'] = cve['cve']
                
        returnData.append(item)
                
    return  returnData


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
    print("\n- INITIATING MEND PARSING - ")
    global competitorData, manifestData, cveData
    global competitorManifestFile, competitorCVEsFile, outputFile
    competitorManifestFile = "input/" + settings.compShort + "/" + settings.compShort + "_" + settings.appShort + "_manifest.txt" # In the input folder
    competitorCVEsFile = "input/" + settings.compShort + "/" + settings.compShort + "_" + settings.appShort + "_html_cves.csv" # In the input folder
    outputFile = "processedFiles/" + settings.compShort + "/dependency-check-report-processed-" + settings.appShort + "-" + settings.compShort + ".csv"

    import_reports()

    print("\nResults written to '" + outputFile + "'...")
    
    format_csv_report() #Print report in CSV format
    
if __name__ == "__main__":
    main()
