#!/usr/bin/python
import json

#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
    file = open("../input/snyk-report.json", "r")
    # print(file.read())
    res = json.loads(file.read())
    file.close()
    # print("Found "+str(len(res["components"]))+" components...\n")
    items = 0
    for i in res:
        items = items+len(i)
    print("Found "+str(items)+" vulnerabilities...\n")

    # print("Parsing component names...")
    # extensions = [
    #     ".zip",
    #     ".jar",
    #     ".pom",
    #     ".tar.gz"
    #     ".tgz",
    #     ".zip"
    #     ".whl"
    # ]

    components = "format,Component,CVEs,score\n"
    for format in res:
        for i in format["vulnerabilities"]:
            # cName = ""
            # if i["packageManager"] == 'npm':
            #     cName = i["name"]+"@"+i["version"]
            # elif i["packageManager"] == 'maven':
            cName = i["name"]+":"+i["version"]

            if len(i["version"]) > 0:
                
                if len(i["identifiers"]["CVE"])>0:
                    for j in i["identifiers"]["CVE"]:
                        components+=i["packageManager"]+","
                        components+=cName+","
                        components+=j+","
                        components+=str(i["cvssScore"])+"\n"
                else:
                    # print(cName)
                    components+=i["packageManager"]+","
                    components+=cName+","
                    components+=i["id"]+","
                    components+=str(i["cvssScore"])+"\n"

                for j in i["from"]:
                    components+=i["packageManager"]+","
                    components+=j.replace("@", ":")+",,\n"

                    # if i["packageManager"] == 'maven':
                    #     jj = j.replace("@", ":")
                    #     components+=jj+",,\n"
                    # else:
                    #     components+=j+",,\n"
                    

                
                # if i["version"] in cName:
                #     cName = cName.split("-"+i["version"])
                #     cName.pop()           
                #     cName = ''.join(cName)
                # Get Licenses
                # lics = []
                # for j in i["licenses"]:
                #     if "license" in j:
                #         if "id" in j["license"]:
                #             lics.append(j["license"]["id"])
                #         elif "name"in j["license"]:
                #             lics.append(j["license"]["name"])
                    

                # Associate CVEs to Components
                # cves = []
                # for j in res["vulnerabilities"]:
                #     for k in j["affects"]:
                #         if i["bom-ref"] in k["ref"]:
                #             cves.append(j["id"])
                    
                # Append to list
                # components.append({
                #     "component": cName,
                #     "cve": cves,
                #     "licenses": lics
                # })
            else:
                print("\tCompetitor SBOM component version not found: "+i["name"])

    print(components)

    f = open("snyk-report.csv", "w")
    f.write(components)
    f.close()