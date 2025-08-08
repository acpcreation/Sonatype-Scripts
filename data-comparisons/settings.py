""" Configuration File
Modify this file for your environment and intended results """


# IQ Server Configurations
baseURL = "http://localhost:8070/" #URL including trailing '/'
username = "admin"
password = "admin!23"
stage = "build" # possible values: [source | build | stage-release | release] - use source for CityState

competitorSBOM = "SkyportMendCycloneDX-bom.json" # In the input folder
# Ensure the `competitorSBOM` .csv file has collumn headers `Components` and `CVEs`.

#Optional Configurations: 
sonatypeSBOM = "sonatype-bom.json" # Automatically created by pulling from IQ directly
enhancedDataFile = "enhanced-data.json"
#First time through you need to run all 3 function (ie: set to True)
# You only need to run `getAPIRemediationData()` and `deeperDataStats()` once (and it takes a while).
isApiRemediationData = True
isDeeperDataStats = True