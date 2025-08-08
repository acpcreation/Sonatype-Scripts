""" Configuration File
Modify this file for your environment and intended results """


#IQ Server Configurations
baseURL = "http://localhost:8070/" #URL including trailing '/'
username = "admin"
password = "admin!23"

applicationID = "WebGoat"
appShort = "WebGoat"
stage = "build" # possible values: [source | build | stage-release | release] - use source for CityState
compShort = "jfrog" # possible values: [google | jfrog | HCL | OWASP | mend | snyk]

#Optional Configurations
compareLicenses = False # Only set to true if license data is included in the competitor SBOM.

#Optional Configurations: 
#First time through you need to run all 3 function (ie: set to True)
# You only need to run `getAPIRemediationData()` and `deeperDataStats()` once (and it takes a while).
isApiRemediationData = False
isDeeperDataStats = False
isMergeLicenses = False

#appshort examples: "NodeGoat" "struts2rce" "Tusimple" "WebGoat"
