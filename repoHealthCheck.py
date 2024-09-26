#!/usr/bin/env python
import json
import requests

#
# This script gets a list of all the components in your artifact repository
# and generates a CycloneDX file which we can then scan with Sonatype Lifecycle
# to generate an SBOM report that is easy to share and navigate.
#
# Note: for Artifactory we use the AQL to search. To get contents from remote repos 
# in Artifactory you must add "-cache" to the end of the repo name. Might be several 
# unknown components for component groups/bundles.
# Tested on Artifactory Maven, Npm, and PyPi remote cache repos.
#

# ========= ENVIRONMENT VARIABLES ========
url = "http://localhost:8081/" #URL including trailing '/'
username = "admin"
password = "admin!23"
auditRepository = "npm-malicious"
repoManager = "nexus" # Options: [ nexus, artifactory ]

# =============================================

# Optional Configurations
useArtifactoryRawOutputCache = False # Local raw-out.json
typeIdentifiers = [
    {
        "extension":".jar",
        "type":"maven"
    },
    {
        "extension":".pom",
        "type":"maven"
    },
    {
        "extension":".tgz",
        "type":"npm"
    },
    {
        "extension":".json",
        "type":"npm"
    },
    {
        "extension":".whl",
        "type":"pypi"
    },
    {
        "extension":".tar.gz",
        "type":"pypi"
    },
    {
        "extension":".zip",
        "type":"pypi"
    },
    {
        "extension":".html",
        "type":"generic"
    }
]

# Default variables
components = []

def get_nexus_components():
    print("Getting list of components from Sonatype Nexus!")
    global url, components
    res = requests.get(url+"service/rest/v1/components?repository="+auditRepository, auth=(username, password)) #, timeout=120
    if res.text != "":
        res = json.loads(res.text)
        components = components + res["items"]
        contToken = res["continuationToken"]
        while contToken != None:
            print("\t Next page... "+contToken)
            res = requests.get(url+"service/rest/v1/components?repository="+auditRepository+"&continuationToken="+contToken, auth=(username, password)) #, timeout=120
            # print(res.text)
            res = json.loads(res.text)
            components = components + res["items"]
            contToken = res["continuationToken"]

        convert_nexus_to_cyclonedx(components)
    
    else:
        print("OOPS! The repository '"+auditRepository+"' was not found! Are your credentials correct? Does the repo exist?")


def convert_nexus_to_cyclonedx(e):
    print("Converting Nexus results to CycloneDX")
    sbomComponents = []
    for i in e:
        comp = {
            "name" : i["name"],
            "version" : i["version"],
            "hashes" : [
              {
                "alg" : "SHA-1",
                "content" : i["assets"][0]["checksum"]["sha1"]
              }
            ],
            "type" : "library",
            "bom-ref" : i["assets"][0]["path"]
        },
        if i["group"] != None:
            comp["group"] : i["group"]
        
        sbomComponents += comp

    sbom =  {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:1dba4a68-e028-4ff0-886b-c52d6a9655f1",
        "version": 1,
        "components": sbomComponents
    }
    write_to_file(sbom)


def get_artifactory_components():
    print("Getting list of components from JFrog Artifactory!")
    global url, components
    payload = "items.find({\"repo\":\""+auditRepository+"\"})"
    headers={'content-type': 'text/plain'}
    # res = requests.get(url+"artifactory/api/search/artifact?name=*&repos="+auditRepository, auth=(username, password)) #, timeout=120
    # https://www.shellhacks.com/artifactory-api-list-artifacts-in-repository-curl/
    res = requests.post(url+"artifactory/api/search/aql/", data=payload, headers=headers, auth=(username, password)) #, timeout=120
    if res.text != "":
        # print(res.text)
        print("Writing raw output to file...")
        f = open("raw-out.json", "w")
        f.write(res.text)
        f.close()
        print("Raw output from Artifactory written to `raw-out.json`\n")

        res = json.loads(res.text)
        print("Found "+str(len(res["results"]))+" components...")
        convert_artifactory_to_cyclonedx(res["results"])
    else:
        print("OOPS! The repository '"+auditRepository+"' was not found! Are your credentials correct? Does the repo exist?")


def get_artifactory_components_from_cache():
    print("Reading Artifactory components from local `raw-out.json` cache file.")
    try:
        file = open("raw-out.json", "r")
        # print(file.read())
        res = json.loads(file.read())
        file.close()
        print("Found "+str(len(res["results"]))+" components...")
        convert_artifactory_to_cyclonedx(res["results"])
    except OSError as e:
        print(e)


def convert_artifactory_to_cyclonedx(e):
    print("Converting Artifactory results to CycloneDX.")
    sbomComponents = []
    unidentifiedTypes = []
    uniqueItems = [None]
    for i in e:
        cType = ""
        cName = i["name"]
        cVersion = ""
        typeFound = False
        skip = False

        for j in typeIdentifiers:
            if j["extension"] in cName:
                typeFound = True
                cType = j["type"]
                cName = cName.replace(j["extension"],"") # remove extension

                # Parse version based on type
                match j["type"]:
                    case "maven":
                        cName = i["path"]
                        cName = cName.split("/")
                        cVersion = cName.pop()
                        tempName = cName.pop()
                        cName = '.'.join(cName)
                        cName += "/"+tempName
                    case "npm":
                        cName = cName.split("-")
                        cVersion = cName.pop()
                        cName = '-'.join(cName)
                        if cVersion == "package":
                            skip = True
                    case "pypi":
                        # print(i)
                        cName = cName.replace("-py3-none-any","")
                        cName = cName.replace("-py2.py3-none-an","")
                        cName = cName.split("-")
                        cVersion = cName.pop()
                        cName = '-'.join(cName)
                    # case _:
                    #   print(i["name"]+" > "+cName+"@"+cVersion) 
                
                break

        if typeFound == False:
            warn = "\t Component type not identified: "+i["name"]+" | PATH="+i["path"]
            print(warn)
            unidentifiedTypes.append(warn)
        purl = "pkg:"+cType+"/"+cName+"@"+cVersion
        comp = {
            "name": cName,
            "version": cVersion,
            "purl": purl,
            "bom-ref": i["path"]+"/"+i["name"],
            "type": "library"
        },

        if skip == False:
            if purl not in uniqueItems:
                sbomComponents += comp
                uniqueItems.append(purl)

    if len(unidentifiedTypes) > 0:
        print("\nWARNING!")
        print("Oops! A couple of components could not be matched to a type. Please review the above log output and add the `Extension` and `Type` to the `typeIdentifiers` object around line 33. Warnings written to `warnings.log`.")
        print("\n")
        f = open("warnings.json", "w")
        f.write(json.dumps(unidentifiedTypes))
        f.close()
    
    print("Cleaned up "+str(len(e)-(len(uniqueItems)-1))+ " duplicates. "+str(len(uniqueItems)-1)+" unique items remaining.")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:1dba4a68-e028-4ff0-886b-c52d6a9655f1",
        "version": 1,
        "components": sbomComponents
    }
    write_to_file(sbom)

    # csvString = ""
    # for i in sbomComponents:
    #     csvString += i["name"]+" : "+ i["version"]+" , "+i["purl"]+"\n"
    # f = open("temp.csv", "w")
    # f.write(csvString)
    # f.close()


def write_to_file(e):
    fileName = repoManager+"-"+auditRepository+"-bom.json"
    f = open(fileName, "w")
    f.write(json.dumps(e))
    f.close()
    print("\nDone! Results written to '"+fileName+"'")
    print("Scan these results with Sonatype Lifecycle to get the health check results!")


#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":

    if repoManager == "nexus":
        get_nexus_components()
    elif repoManager == "artifactory" and useArtifactoryRawOutputCache == False:
        get_artifactory_components()
    elif repoManager == "artifactory" and useArtifactoryRawOutputCache == True:
        get_artifactory_components_from_cache()
    else:
        print("ERROR: Repository `"+repoManager+"` not found.")
    
