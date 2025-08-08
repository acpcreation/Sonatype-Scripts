#!/usr/bin/env python
import json
import csv
import math
import prework_settings

# ========= ENVIRONMENT VARIABLES ========
competitorFile = "processedFiles/OWASP/dependency-check-report-processed-" + prework_settings.appShort + "-OWASP.csv"
npmProcessedFile = "processedFiles/prework/npm-list-processed-" + prework_settings.appShort + ".txt"
outputFile = "output/prework/npm-comparison-" + prework_settings.appShort + "-OWASP.json"
# =============================================

competitorData = []
npmData = []

#global comparisonData
comparisonData = {
    "componentsFoundByNpm":0,
    "componentsFoundByCompetitor":0,
    "additionalCompetitorComponents": [],
    "additionalCompetitorComponentsLength":0,
    "componentsUsed":[],
    "componentsUsedLength":0,
    "fuzzyComponentsUsed":[],
    "fuzzyComponentsUsedLength":0,
    "additionalNpmComponents": [],
    "additionalNpmComponentsLength":0,
}


#Read both SBOMs
def import_reports():
    print("Reading "+competitorFile+"... ")
    jf = open(competitorFile, "r")

    global competitorData
    if competitorFile.endswith(".csv"):
        cols = {
            "identifier":None,
            "type":None
        }
        indexSet = False

        csvData = csv.reader(jf)
        for lines in csvData:
            
            # Determine value columns
            if indexSet == False:
                cols = get_column_indicies(cols, lines)
                indexSet = True
            else:
                component = lines[cols["identifier"]]    
                competitorData.append(component)

        competitorData.sort()
        jf.close()
        comparisonData["componentsFoundByCompetitor"] = len(competitorData)

    else:
        print("ERROR COMPETITOR SBOM ", competitorLicenseExport, " NOT COMPATIBLE!")
        quit()

    print("Reading "+npmProcessedFile+"... ")
    mf = open(npmProcessedFile, "r")
    npmProcessedData = csv.reader(mf)
    
    global npmData
    for i in npmProcessedData:
        if i[0].startswith("##"):
            continue
        compName = i[0]
        npmData.append(compName)

    npmData.sort()
    comparisonData["componentsFoundByNpm"] = len(npmData)
    mf.close()

    print("Competitor found : " + str(comparisonData["componentsFoundByCompetitor"]))
    print("Npm found           : " + str(comparisonData["componentsFoundByNpm"]))


def get_column_indicies(cols, lines):
    print("\tFound column headers: ")
    for i in range(len(lines)):
        item = lines[i].lower()
        print("\t\t- <"+item+">")
        if item == "components" or item == "component":
            cols["identifier"] = i
        if item == "package type":
            cols["type"] = i

    return cols


#Compare the actual components
def compare_components():
    preUsed = []
    uniqueUsed = []
    preNpm = []
    uniqueNpm = []

    print("\nComparing components found by both tools...")
    for i in range(len(competitorData)):
        competitorComponent = competitorData[i] 

        for j in range(len(npmData)):
            npmComponent = npmData[j]
            if competitorComponent ==  npmComponent:
                 preUsed.append(npmData[j])

    for pu in range(len(preUsed)):
        usedStr = preUsed[pu]

        found = False
        for uu in range(len(uniqueUsed)):
            uusedStr = uniqueUsed[uu]

            if usedStr == uusedStr:
                found = True

        if found == False:
            uniqueUsed.append(preUsed[pu])

    for i in range(len(competitorData)):
        found = False
        competitorComponent = competitorData[i] 

        for us in range(len(uniqueUsed)):
            usedStr = uniqueUsed[us]
            if competitorComponent == usedStr:
                found = True
                break

        if not found:    
            for j in range(len(npmData)):
                npmComponent = npmData[j]
                parts = competitorData[i].split(":")
                compStr = parts[0] + ":"
                if compStr in npmComponent:
                    found = True
                    comparisonData["fuzzyComponentsUsed"].append(npmComponent + "<>" + parts[1])
                    comparisonData["fuzzyComponentsUsedLength"]+=1

        if found == False:
            comparisonData["additionalCompetitorComponents"].append(competitorComponent)
            comparisonData["additionalCompetitorComponentsLength"]+=1

    print("\nWhat was missed ???")
    for j in range(len(npmData)):
        found = False
        compStr = npmData[j]

        for us in range(len(uniqueUsed)):
            usedStr = uniqueUsed[us]
            if compStr == usedStr:
                found = True
                break
        
        if not found:
            for fcu in range(len(comparisonData["fuzzyComponentsUsed"])):
                fuzzyStr = comparisonData["fuzzyComponentsUsed"][fcu]
                if compStr in fuzzyStr:
                    found = True
                    break

        if not found:
            preNpm.append(compStr)

    for n in range(len(preNpm)):
        npmStr = preNpm[n]

        found = False
        for un in range(len(uniqueNpm)):
            unpmStr = uniqueNpm[un]

            if npmStr == unpmStr:
                found = True

        if found == False:
            uniqueNpm.append(preNpm[n])

    comparisonData["componentsUsed"] = uniqueUsed
    comparisonData["componentsUsedLength"] = len(uniqueUsed)
    comparisonData["additionalNpmComponents"] = uniqueNpm
    comparisonData["additionalNpmComponentsLength"] = len(uniqueNpm)

    print("Additional Competitor \t: "  + str(comparisonData["additionalCompetitorComponentsLength"]))
    print("Used                          \t: " + str(comparisonData["componentsUsedLength"]))
    print("Fuzzy Used                \t: "  + str(comparisonData["fuzzyComponentsUsedLength"]))
    print("Additional Npm         \t: "  + str(comparisonData["additionalNpmComponentsLength"]))
#    print("Stop here!!")

#==========================
#========== MAIN ==========
#==========================

def main(e):
    #compareData
    print("\n- INITIATING DATA COMPARISON - ")
    global npmProcessedFile, competitorFile
    competitorFile= e["competitorFile"]
    npmProcessedFile = e["npmProcessedFile"]

    import_reports()
    compare_components()   

    # Write to file
    f = open(outputFile, "w")
    f.write(json.dumps(comparisonData))
    f.close()
    print("\nResults written to '" + outputFile + "'...")

    
if __name__ == "__main__":
    main({
        "competitorFile": competitorFile,
        "npmProcessedFile":npmProcessedFile
    })