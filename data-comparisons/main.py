#!/usr/bin/python
import settings

from getAPIRemediationData import main as getAPIRemediationData
from deeperDataStats import main as deeperDataStats
from compareData import main as compareData


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
        "sonatypeSBOM": "input/"+settings.sonatypeSBOM,
    }

    # You only need to run the `getAPIRemediationData(apiEnv)` and `deeperDataStats()` once (and it takes a while).
    # If you want to play with the data to get the results you want, comment out the functions except for the comparData() function.
    
    # First time through need to run all three functions
    if settings.isApiRemediationData: getAPIRemediationData(apiEnv)

    if settings.isDeeperDataStats: deeperDataStats({"sonatypeSBOM": "input/"+settings.sonatypeSBOM, "enhancedDataFile": "output/"+settings.enhancedDataFile})


    compareDataData = {
        "competitorSBOM":"input/"+settings.competitorSBOM,
        "sonatypeSBOM": "input/"+settings.sonatypeSBOM,
        "csvOutputFile": "output/csv-data-comparison.csv",
        "jsonOutputFile": "output/data-comparison.json",
    }
    
    compareData(compareDataData)
