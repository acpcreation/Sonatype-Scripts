#!/usr/bin/python
import os
import settings

from getAPIRemediationData import main as getAPIRemediationData
from deeperDataStats import main as deeperDataStats
from compareData import main as compareData

from mergeLicenses import main as mergeLicenses

from parsers.parseGoogle import main as parseGoogle
from parsers.parsejFrog import main as parsejFrog
from parsers.parseHCL import main as parseHCL
from parsers.parseOWASP import main as parseOWASP
from parsers.parseMend import main as parseMend
from parsers.parseSnyk import main as parseSnyk

competitorSBOM = "processedFiles/" + settings.compShort + "/dependency-check-report-processed-" + settings.appShort + "-" + settings.compShort + ".csv"
sonatypeSBOM = "processedFiles/sonatype/sonatype-sbom-" + settings.appShort + ".json" # Automatically created by pulling from IQ directly
sonatypeLicsFile = "processedFiles/sonatype/sonatype-licenses-" + settings.appShort + ".json" # Automatically created by pulling from IQ directly
masterLicsFile = "processedFiles/sonatype/sonatype-master-licenses.json"
csvOutputFile = "output/" + settings.compShort + "/competitor-data-comparison-" + settings.appShort + "-" + settings.compShort + ".csv"
jsonOutputFile = "output/" + settings.compShort + "/data-comparison-" + settings.appShort + "-" + settings.compShort + ".json"
enhancedDataFile = "output/sonatype/enhancedData-" + settings.appShort + ".json"

# Ensure the `competitorSBOM` has collumn headers `Components` and `CVEs`.


#Configure the functions in the Main to determine what data to get.
#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    print("\n#####################################")
    print("STARTING THE FULL DATA COMPARISON")
    print("#####################################")

    apiEnv = {
        "applicationID": settings.applicationID,
        "url":settings.baseURL,
        "username":settings.username,
        "password":settings.password,
        "stage":settings.stage,
        "sonatypeSBOM": sonatypeSBOM,
        "sonatypeLicsFile": sonatypeLicsFile
    }

    os.makedirs("processedFiles/" + settings.compShort, exist_ok=True)
    os.makedirs("output/" + settings.compShort, exist_ok=True)

    # You only need to run the `getAPIRemediationData(apiEnv)` and `deeperDataStats()` once (and it takes a while).
    # If you want to play with the data to get the results you want, comment out the functions except for the comparData() function.
    
    # First time through need to run all three functions
    if settings.isApiRemediationData: getAPIRemediationData(apiEnv)

    if settings.isDeeperDataStats: deeperDataStats({"sonatypeSBOM": sonatypeSBOM, "enhancedDataFile": enhancedDataFile})

    if settings.isMergeLicenses: mergeLicenses({"sonatypeLicsFile": sonatypeLicsFile,"masterLicsFile":masterLicsFile})

    if settings.compShort == "google":
        print("parseGoogle")
        parseGoogle()
    elif settings.compShort == "jfrog":
        print("parseJFrog")
        parsejFrog()
    elif settings.compShort == "HCL":
        print("parseHCL")
        parseHCL()
    elif settings.compShort == "OWASP":
        print("parseOWASP")
        parseOWASP()
    elif settings.compShort == "mend":
        print("parseMend")
        parseMend()
    elif settings.compShort == "snyk":
        print("parseSnyk")
        parseSnyk()
    else:
        print("Well this is awkward")
        print("ERROR: No parser found. Double check your selection exists.")
        quit ()

    compareDataData = {
        "competitorSBOM":competitorSBOM,
        "sonatypeSBOM": sonatypeSBOM,
        "masterLicsFile": masterLicsFile,
        "csvOutputFile": csvOutputFile,
        "jsonOutputFile": jsonOutputFile,
        "checkLicenses": settings.compareLicenses
    }
    
    compareData(compareDataData)
