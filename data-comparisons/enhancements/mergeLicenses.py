#!/usr/bin/env python
import json
import csv
import math
import settings

# ========= ENVIRONMENT VARIABLES ========
sonatypeLicsFile = "processedFiles/sonatype-licenses-" + settings.appShort + ".json"
masterLicsFile = "processedFiles/sonatype-master-licenses.json"
# =============================================

appLicenses = []
masterLicenses = []


#Read both SBOMs
def import_files():
    global appLicenses, masterLicenses
    appLicenses = read_appLicenses()
    masterLicenses = read_masterLicenses()
    print("Read " + str(len(masterLicenses["licenseSingleLegalMeta"])) + " single licenses")
    print("Read " + str(len(masterLicenses["licenseMultiLegalMeta"])) + " multi licenses")
    masterLicenses = process_components(appLicenses, masterLicenses)
    print("Processed " + str(len(masterLicenses["licenseSingleLegalMeta"])) + " single licenses")
    print("Processed " + str(len(masterLicenses["licenseMultiLegalMeta"])) + " multi licenses")


#Parse competitor data file
def read_appLicenses():
    print("Reading "+sonatypeLicsFile+"... ")
    f = open(sonatypeLicsFile, "r")
    appLicenses = json.load(f)
    f.close()
    return appLicenses


#Parse competitor data file
def read_masterLicenses():
    print("Reading "+masterLicsFile+"... ")
    f = open(masterLicsFile, "r")
    masterLicenses = json.load(f)
    f.close()
    return masterLicenses


def process_components(appLicenses, masterLicenses):
    print("Process the two data files")
    appSingleLicenses = appLicenses["licenseSingleLegalMeta"]
    appMultiLicenses = appLicenses["licenseMultiLegalMeta"]
    uniqueSingleLicenses = masterLicenses["licenseSingleLegalMeta"]
    uniqueMultiLicenses = masterLicenses["licenseMultiLegalMeta"]
    uniqueLicenses = {}
    
    for appLic in appSingleLicenses:
        if appLic not in uniqueSingleLicenses:
            uniqueSingleLicenses[appLic] = appSingleLicenses[appLic]
            print("Added a new license to the Single Master: " + appLic)
    
    for appLic in appMultiLicenses:
        if appLic not in uniqueMultiLicenses:
            uniqueMultiLicenses[appLic] = appMultiLicenses[appLic]
            print("Added a new license to the Multi Master: " + appLic)

    uniqueLicenses["licenseSingleLegalMeta"] = uniqueSingleLicenses
    uniqueLicenses["licenseMultiLegalMeta"] = uniqueMultiLicenses

    return uniqueLicenses


#==========================
#========== MAIN ==========
#==========================

def main(e):
    print("\n- INITIATING MVN PARSING - ")
    global sonatypeLicsFile, masterLicsFile
    sonatypeLicsFile = e["sonatypeLicsFile"]
    masterLicsFile = e["masterLicsFile"]

    import_files()
    
    f = open(masterLicsFile, "w")
    f.write(json.dumps(masterLicenses))
    f.close()
    print("Results written to "+masterLicsFile+"\'")

    
if __name__ == "__main__":
    main({
        "sonatypeLicsFile":sonatypeLicsFile,
        "masterLicsFile":masterLicsFile,
    })
    