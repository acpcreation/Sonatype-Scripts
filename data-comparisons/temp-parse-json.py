#!/usr/bin/python
import json

#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    file = open("input/SkyportMendCycloneDX-bom.json", "r")
    # print(file.read())
    res = json.loads(file.read())
    file.close()
    print("Found "+str(len(res["components"]))+" components...\n")

    print("Parsing component names...")
    # extensions = [
    #     ".zip",
    #     ".jar",
    #     ".pom",
    #     ".tar.gz"
    #     ".tgz",
    #     ".zip"
    #     ".whl"
    # ]

    components = []

    for i in res["components"]:
        cName = i["name"]
        if len(i["version"]) > 0:
            if i["version"] in cName:
                cName = cName.split("-"+i["version"])
                cName.pop()           
                cName = ''.join(cName)

            cName = cName+":"+i["version"]
            if i["group"] != "NONE":
                cName = i["group"]+":"+cName
            # print(cName)

            # Get Licenses
            lics = []
            for j in i["licenses"]:
                if "license" in j:
                    if "id" in j["license"]:
                        lics.append(j["license"]["id"])
                    elif "name"in j["license"]:
                        lics.append(j["license"]["name"])
                

            # Associate CVEs to Components
            cves = []
            for j in res["vulnerabilities"]:
                for k in j["affects"]:
                    if i["bom-ref"] in k["ref"]:
                        cves.append(j["id"])
                
            # Append to list
            components.append({
                "component": cName,
                "cve": cves,
                "licenses": lics
            })
        else:
            print("\tCompetitor SBOM component version not found: "+i["name"])

