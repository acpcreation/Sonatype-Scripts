#!/usr/bin/env python
import json
import csv
import math
import prework_settings

# ========= ENVIRONMENT VARIABLES ========
sonatypeSBOM = "processedFiles/sonatype/sonatype-sbom-" + prework_settings.appShort + ".json"
npmProcessedFile = "processedFiles/prework/npm-list-processed-" + prework_settings.appShort + ".txt"
outputFile = "output/prework/npm-comparison-" + prework_settings.appShort + "-sonatype.json"
# =============================================

sonatypeData = []
npmData = []

#global comparisonData
comparisonData = {
    "componentsFoundByNpm":0,
    "componentsFoundBySonatype":0,
    "additionalSonatypeComponents": [],
    "additionalSonatypeComponentsLength":0,
    "componentsUsed":[],
    "componentsUsedLength":0,
    "fuzzyComponentsUsed":[],
    "fuzzyComponentsUsedLength":0,
    "additionalNpmComponents": [],
    "additionalNpmComponentsLength":0,
}


#Read both SBOMs
def import_reports():
    print("Reading "+sonatypeSBOM+"... ")
    sf = open(sonatypeSBOM, "r")
    jsonData = json.load(sf)

    print("Reading "+npmProcessedFile+"... ")
    mf = open(npmProcessedFile, "r")
    npmProcessedData = csv.reader(mf)

    global sonatypeData
    for i in jsonData:
        if i["packageUrl"] == None:
            continue
        #Get component name
        compName = i["displayName"]
        if ":" not in compName:
            compName = compName.replace(" ", ":")
        compName = compName.replace(" ", "")
        sonatypeData.append(compName)

    sonatypeData.sort()
    comparisonData["componentsFoundBySonatype"] = len(sonatypeData)
    sf.close()
    
    global npmData
    for i in npmProcessedData:
        if i[0].startswith("##"):
            continue
        compName = i[0]
        npmData.append(compName)

    npmData.sort()
    comparisonData["componentsFoundByNpm"] = len(npmData)
    mf.close()

    print("Sonatype found : " + str(comparisonData["componentsFoundBySonatype"]))
    print("Npm found        : " + str(comparisonData["componentsFoundByNpm"]))


#Compare the actual components
def compare_components():
    preUsed = []
    uniqueUsed = []
    preNpm = []
    uniqueNpm = []

    print("\nComparing components found by both tools...")
    for i in range(len(sonatypeData)):
        sonatypeComponent = sonatypeData[i] 

        for j in range(len(npmData)):
            npmComponent = npmData[j]
            if sonatypeComponent ==  npmComponent:
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

    for i in range(len(sonatypeData)):
        found = False
        sonatypeComponent = sonatypeData[i] 

        for us in range(len(uniqueUsed)):
            usedStr = uniqueUsed[us]
            if sonatypeComponent == usedStr:
                found = True
                break

        if not found:    
            for j in range(len(npmData)):
                npmComponent = npmData[j]
                parts = sonatypeData[i].split(":")
                compStr = parts[0] + ":"
                if compStr in npmComponent:
                    found = True
                    comparisonData["fuzzyComponentsUsed"].append(npmComponent + "<>" + parts[1])
                    comparisonData["fuzzyComponentsUsedLength"]+=1

        if found == False:
            comparisonData["additionalSonatypeComponents"].append(sonatypeComponent)
            comparisonData["additionalSonatypeComponentsLength"]+=1

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

    print("Additional Sonatype \t: "  + str(comparisonData["additionalSonatypeComponentsLength"]))
    print("Used                     \t: " + str(comparisonData["componentsUsedLength"]))
    print("Fuzzy Used           \t: "  + str(comparisonData["fuzzyComponentsUsedLength"]))
    print("Additional Npm   \t: "  + str(comparisonData["additionalNpmComponentsLength"]))
#    print("Stop here!!")

#==========================
#========== MAIN ==========
#==========================

def main(e):
    #compareData
    print("\n- INITIATING DATA COMPARISON - ")
    global npmProcessedFile, sonatypeSBOM
    sonatypeSBOM = e["sonatypeSBOM"]
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
        "sonatypeSBOM": sonatypeSBOM,
        "npmProcessedFile":npmProcessedFile
    })