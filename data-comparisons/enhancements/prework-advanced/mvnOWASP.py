#!/usr/bin/env python
import json
import csv
import math
import prework_settings

# ========= ENVIRONMENT VARIABLES ========
competitorFile = "../processedFiles/OWASP/dependency-check-report-processed-" + prework_settings.appShort + "-OWASP.csv"
mvnProcessedFile = "../processedFiles/prework/mvn-depend-processed-" + prework_settings.appShort + ".txt"
outputFile = "../output/prework/mvn-comparison-" + prework_settings.appShort + "-OWASP.json"
# =============================================

competitorData = []
mvnData = []

#global comparisonData
comparisonData = {
    "componentsFoundByMaven":0,
    "componentsFoundByCompetitor":0,
    "additionalCompetitorComponents": [],
    "additionalCompetitorComponentsLength":0,
    "componentsUsed":[],
    "componentsUsedLength":0,
    "usedUndeclaredComponents":[],
    "usedUndeclaredComponentsLength":0,
    "unusedDeclaredComponents":[],
    "unusedDeclaredComponentsLength":0,
    "fuzzyComponentsUsed":[],
    "fuzzyComponentsUsedLength":0,
    "fuzzyUsedUndeclaredComponents":[],
    "fuzzyUsedUndeclaredComponentsLength":0,
    "fuzzyUnusedDeclaredComponents":[],
    "fuzzyUnusedDeclaredComponentsLength":0,
    "additionalMavenComponents": [],
    "additionalMavenComponentsLength":0,
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

    print("Reading "+mvnProcessedFile+"... ")
    mf = open(mvnProcessedFile, "r")
    mvnProcessedData = csv.reader(mf)

    global mvnData
    for i in mvnProcessedData:
        if i[0].startswith("##"):
            continue
        compName = i[0]
        mvnData.append(compName)

    mvnData.sort()
    comparisonData["componentsFoundByMaven"] = len(mvnData)
    mf.close()

    print("Competitor found : " + str(comparisonData["componentsFoundByCompetitor"]))
    print("Maven found     : " + str(comparisonData["componentsFoundByMaven"]))


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
    preMvn = []
    uniqueMvn = []

    print("\nComparing components found by both tools...")
    for i in range(len(competitorData)):
        found = False
        usedFound = False
        unusedFound = False
        alreadyFound = False

#        if competitorData[i] == "com.fasterxml.jackson.core:jackson-annotations:2.13.3":
#            print("Stop here!!")

        for j in range(len(mvnData)):
            if competitorData[i] in mvnData[j]:
                found = True
                if mvnData[j].startswith("U_UD_"):
                    comparisonData["usedUndeclaredComponents"].append(mvnData[j])
                    comparisonData["usedUndeclaredComponentsLength"]+=1
                    usedFound = True
                if mvnData[j].startswith("UU_D_"):
                    comparisonData["unusedDeclaredComponents"].append(mvnData[j])
                    comparisonData["unusedDeclaredComponentsLength"]+=1
                    unusedFound = True
                if not usedFound and not unusedFound and not alreadyFound:
                    comparisonData["componentsUsed"].append(mvnData[j])
                    comparisonData["componentsUsedLength"]+=1
                alreadyFound = True
            else:
                parts = competitorData[i].split(":")
                if len(parts) < 2:
                    print("Stop here!!")

                compStr = parts[0] + ":" + parts[1] + ":"
                if compStr in mvnData[j]:
                    found = True
                    if mvnData[j].startswith("U_UD_"):
                        comparisonData["fuzzyUsedUndeclaredComponents"].append(mvnData[j] + "<>" + parts[2])
                        comparisonData["fuzzyUsedUndeclaredComponentsLength"]+=1
                        usedFound = True
                    if mvnData[j].startswith("UU_D_"):
                        comparisonData["fuzzyUnusedDeclaredComponents"].append(mvnData[j] + "<>" + parts[2])
                        comparisonData["fuzzyUnusedDeclaredComponentsLength"]+=1
                        unusedFound = True
                    if not usedFound and not unusedFound and not alreadyFound:
                        comparisonData["fuzzyComponentsUsed"].append(mvnData[j] + "<>" + parts[2])
                        comparisonData["fuzzyComponentsUsedLength"]+=1
                    alreadyFound = True

        if found == False:
            comparisonData["additionalCompetitorComponents"].append(competitorData[i])
            comparisonData["additionalCompetitorComponentsLength"]+=1

    print("\nWhat was missed ???")
    for j in range(len(mvnData)):
        found = False
        parts = mvnData[j].split(":")
        compStr = parts[0] + ":" + parts[1] + ":"
        compStr = compStr.replace("U_UD_", "")
        compStr = compStr.replace("UU_D_", "")

#        if compStr == "javax:javaee-api:6.0":
#            print("Stop here!!")

        for i in range(len(competitorData)):
            if compStr in competitorData[i] and not found:
                found = True
#                continue

        if not found:
            preMvn.append(mvnData[j])

    for m in range(len(preMvn)):
        mvnStr = preMvn[m]
        mvnStr = mvnStr.replace("U_UD_", "")
        mvnStr = mvnStr.replace("UU_D_", "")

        found = False
        for u in range(len(uniqueMvn)):
            umvnStr = uniqueMvn[u]
            umvnStr = umvnStr.replace("U_UD_", "")
            umvnStr = umvnStr.replace("UU_D_", "")

            if mvnStr == umvnStr:
                found = True

        if found == False:
            uniqueMvn.append(preMvn[m])

    comparisonData["additionalMavenComponents"] = uniqueMvn
    comparisonData["additionalMavenComponentsLength"] = len(uniqueMvn)

    print("Additional Competitor \t: "  + str(comparisonData["additionalCompetitorComponentsLength"]))
    print("Used Undeclared       \t: "  + str(comparisonData["usedUndeclaredComponentsLength"]))
    print("Unused Declared       \t: "  + str(comparisonData["unusedDeclaredComponentsLength"]))
    print("Use                           \t: " + str(comparisonData["componentsUsedLength"]))
    print("Short Used UnDec     \t: "  + str(comparisonData["fuzzyUsedUndeclaredComponentsLength"]))
    print("Short Unused Dec     \t: "  + str(comparisonData["fuzzyUnusedDeclaredComponentsLength"]))
    print("Short Used                \t: "  + str(comparisonData["fuzzyComponentsUsedLength"]))
    print("Additional Maven      \t: "  + str(comparisonData["additionalMavenComponentsLength"]))


#==========================
#========== MAIN ==========
#==========================

def main(e):
    #compareData
    print("\n- INITIATING DATA COMPARISON - ")
    global mvnProcessedFile, competitorFile
    competitorFile = e["competitorFile"]
    mvnProcessedFile = e["mvnProcessedFile"]

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
        "mvnProcessedFile":mvnProcessedFile
    })