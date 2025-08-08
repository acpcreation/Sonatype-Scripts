#!/usr/bin/env python
import json
import csv
import math
import prework_settings

# ========= ENVIRONMENT VARIABLES ========
sonatypeSBOM = "../processedFiles/sonatype/sonatype-sbom-" + prework_settings.appShort + ".json"
mvnProcessedFile = "../processedFiles/prework/mvn-depend-processed-" + prework_settings.appShort + ".txt"
outputFile = "../output/prework/mvn-comparison-" + prework_settings.appShort + "-sonatype.json"
# =============================================

sonatypeData = []
mvnData = []

#global comparisonData
comparisonData = {
    "componentsFoundByMaven":0,
    "componentsFoundBySonatype":0,
    "additionalSonatypeComponents": [],
    "additionalSonatypeComponentsLength":0,
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
    print("Reading "+sonatypeSBOM+"... ")
    sf = open(sonatypeSBOM, "r")
    jsonData = json.load(sf)

    print("Reading "+mvnProcessedFile+"... ")
    mf = open(mvnProcessedFile, "r")
    mvnProcessedData = csv.reader(mf)

    global sonatypeData
    for i in jsonData:
        if i["packageUrl"] == None:
            continue
        #Get component name
        compName = i["displayName"]
#        if compName.startswith("com.h2database"):
#            print ("Stop here!! " + compName)
        if ":" not in compName:
            compName = compName.replace(" ", ":")
        if ": jar :" in compName:
            print("Weird one!! " + compName)
            parts = compName.split(":")
            if len(parts) == 5:
                compName = parts[0] + ":" + parts[1] + ":" + parts[4]
            else:
                print("Weird one!!")
                quit()

        compName = compName.replace(" ", "")
        sonatypeData.append(compName)

    sonatypeData.sort()
    comparisonData["componentsFoundBySonatype"] = len(sonatypeData)
    sf.close()
    
    global mvnData
    for i in mvnProcessedData:
        if i[0].startswith("##"):
            continue
        compName = i[0]
        mvnData.append(compName)

    mvnData.sort()
    comparisonData["componentsFoundByMaven"] = len(mvnData)
    mf.close()

    print("Sonatype found : " + str(comparisonData["componentsFoundBySonatype"]))
    print("Maven found     : " + str(comparisonData["componentsFoundByMaven"]))


#Compare the actual components
def compare_components():
    premvn = []
    uniquemvn = []

    print("\nComparing components found by both tools...")
    for i in range(len(sonatypeData)):
        found = False
        usedFound = False
        unusedFound = False
        alreadyFound = False

        string = sonatypeData[i]
        if sonatypeData[i].startswith("com.h2database"):
             print("Stop here!! " + string)

        for j in range(len(mvnData)):
            if sonatypeData[i] in mvnData[j]:
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
                parts = sonatypeData[i].split(":")
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
            comparisonData["additionalSonatypeComponents"].append(sonatypeData[i])
            comparisonData["additionalSonatypeComponentsLength"]+=1

    print("\nWhat was missed ???")
    for j in range(len(mvnData)):
        found = False
        parts = mvnData[j].split(":")
        compStr = parts[0] + ":" + parts[1] + ":"
        compStr = compStr.replace("U_UD_", "")
        compStr = compStr.replace("UU_D_", "")

        if sonatypeData[i].startswith("com.h2database"):
             print("Stop here!!")

        for i in range(len(sonatypeData)):
            if compStr in sonatypeData[i] and not found:
                found = True
#                continue

        if not found:
            premvn.append(mvnData[j])

    for m in range(len(premvn)):
        mvnStr = premvn[m]
        mvnStr = mvnStr.replace("U_UD_", "")
        mvnStr = mvnStr.replace("UU_D_", "")

        found = False
        for u in range(len(uniquemvn)):
            umvnStr = uniquemvn[u]
            umvnStr = umvnStr.replace("U_UD_", "")
            umvnStr = umvnStr.replace("UU_D_", "")

            if mvnStr == umvnStr:
                found = True

        if found == False:
            uniquemvn.append(premvn[m])

    comparisonData["additionalMavenComponents"] = uniquemvn
    comparisonData["additionalMavenComponentsLength"] = len(uniquemvn)

    print("Additional Sonatype \t: "  + str(comparisonData["additionalSonatypeComponentsLength"]))
    print("Used Undeclared  \t: "  + str(comparisonData["usedUndeclaredComponentsLength"]))
    print("Unused Declared  \t: "  + str(comparisonData["unusedDeclaredComponentsLength"]))
    print("Use                      \t: " + str(comparisonData["componentsUsedLength"]))
    print("Short Used UnDec\t: "  + str(comparisonData["fuzzyUsedUndeclaredComponentsLength"]))
    print("Short Unused Dec\t: "  + str(comparisonData["fuzzyUnusedDeclaredComponentsLength"]))
    print("Short Used           \t: "  + str(comparisonData["fuzzyComponentsUsedLength"]))
    print("Additional Maven \t: "  + str(comparisonData["additionalMavenComponentsLength"]))
#    print("Stop here!!")

#==========================
#========== MAIN ==========
#==========================

def main(e):
    #compareData
    print("\n- INITIATING DATA COMPARISON - ")
    global mvnProcessedFile, sonatypeSBOM
    sonatypeSBOM = e["sonatypeSBOM"]
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
        "sonatypeSBOM": sonatypeSBOM,
        "mvnProcessedFile":mvnProcessedFile
    })