#!/usr/bin/env python
import json
import csv
import math

from bs4 import BeautifulSoup

# ========= ENVIRONMENT VARIABLES ========
#competitorSBOM = "processedFiles/webgoat_webgoat_202304172022.student_sca.cdx.xml"
#sonatypeSBOM = "processedFiles/WebGoat-Legacy__ajhaigh-IQ-bom.xml"
#appShort = "WebGoat"

competitorSBOM = "../input/sonatype/WGLeg_Evaluate_build-bom.xml"
sonatypeSBOM = "../input/sonatype/WGLeg_Evaluate_release-bom.xml"
appShort = "WebGoat"

#competitorSBOM = "input/jfrog-nodegoat-sbom.json"
#sonatypeSBOM = "input/sonatype-cdx1.4-nodegoat-sbom.json"
#appShort = "nodegoat"

#csvOutputFile = "output/csv-data-comparison-" + settings.appShort + "-" + settings.compShort + ".csv"
#jsonOutputFile = "output/data-comparison-" + settings.appShort + "-" + settings.compShort + ".json"
csvOutputFile = "../output/csv-data-comparison-" + appShort + "-SBOM_BuildRelease.csv"
jsonOutputFile = "../output/data-comparison-" + appShort + "-SBOM_BuildRelease.json"

# =============================================

# global sonatypeData
sCompD = []
#sVulnRS = []
sVulnD = []

cCompD = []
#cVulnRS = []
cVulnD = []

# global comparisonData
comparisonData = {
    "componentsFoundByBoth": 0,
    "uniqueComponentsFoundBySonatype": 0,
    "uniqueComponentsFoundByCompetitor": 0,
    "componentMissedByCompetitor": [],
    "componentMissedByCompetitorLength": 0,
    "additionalCompetitorComponents": [],
    "additionalCompetitorComponentsLength": 0,
    "cveFoundByBoth": 0,
    "cveDiscrepencies": [],
    "cvdDiscrepenciesLength": 0,
    "cveMissingCompetitor": [],
    "cveMissingCompetitorLength": 0,
    "additionalCompetitorCVEs": [],
    "additionalCompetitorCVEsLength": 0,
    "sonatypeFoundLaterUpdatedCVEs": [],
    "10WorstCompontnentsMissedByCompetitor": [],  # Top 10 worst components missed by competitor
    "badLicenseInComponentsMissedByCompetitor": [],  # Components missed by competitor with bad license
    "badLicenseInComponentsMissedByCompetitorLength": 0,
    "licensingDiscrepencies": [],
    "licensingDiscrepenciesLength": 0
}

csvReportFormat = [
    {
        "sonaName": "Sonatype Component Name",
        "sonaCVEs": "Sonatype CVEs",
        "sonaLic": "Sonatype Licenses",
        "sonaPath": "Sonatype Occurence Path",
        "compName": "Competitor Component Name",
        "compCVEs": "Competitor CVEs",
        "compLic": "Competitor Licenses",
        "match": "Confidence",
    }
]


# Read both SBOMs
def import_reports():
    if sonatypeSBOM.endswith(".xml"):
        import_sonatype_xml()
    elif sonatypeSBOM.endswith(".json"):
        import_sonatype_json()
    else:
        quit()
        
    if competitorSBOM.endswith(".xml"):
        import_comp_xml()
    elif competitorSBOM.endswith(".json"):
        import_comp_json()
    else:
        quit()

    comparisonData["uniqueComponentsFoundBySonatype"] = len(sCompD)
    print("Found by Sonatype " + str(len(sCompD)))
    comparisonData["uniqueComponentsFoundByCompetitor"] = len(cCompD)
    print("Found by Competitor " + str(len(cCompD)))


def import_sonatype_xml():
    global sCompD, sVulnRS, sVulnD

    print("Reading " + sonatypeSBOM + "... ")
    with open (sonatypeSBOM, "r") as sbomFile:
        sData = sbomFile.read()
        sBS_data = BeautifulSoup (sData, "xml")
        sBSComps = sBS_data.find('components')
        sBSCompRS = sBSComps.find_all('component')
        for i in sBSCompRS:
            component = i['bom-ref']
            licenses = i.find_all('license')
            licRS = []
            for r in range(len(licenses)):
                if licenses[r].find('id'):
                    lic = licenses[r].find('id').text
                elif licenses[r].find("name"):
                    lic = licenses[r].find('name').text
                else:
                    print("What the ??")
                licRS.append(lic)
            dict = {}
            dict["component"] = component
            dict["licenses"] = licRS
            sCompD.append(dict)

        sVulnRS = sBS_data.find_all('vulnerability')
        for i in sVulnRS:
            id = i.find('id').text
            if id == "sonatype-2014-0015":
                print ("stop here!!")
            targets = i.find_all('target')
            vulnRS = []
            for v in range(len(targets)):
                vuln = targets[v].find('ref').text
                vuln = vuln.replace("?type=jar", "")
                vuln = vuln.replace("?classifier=exec-war&type=jar", "")
                vulnRS.append(vuln)
            dict = {}
            dict["vulnID"] = id
            dict["targets"] = vulnRS
            sVulnD.append(dict)
        sVulnD = sorted(sVulnD, key=lambda item: item["vulnID"])

        # multiple keys
        sortedlist = sorted(sVulnD , key=lambda elem: "%s %s" % (elem['targets'], elem['vulnID']))
        
        sbomFile.close()


def import_sonatype_json():
    global sCompD, sVulnRS, sVulnD

    print("Reading " + sonatypeSBOM + "... ")
    with open (sonatypeSBOM, "r") as sbomFile:
        sData = json.load(sbomFile)
        sComps = sData['components']
        for i in sComps:
            component = i['name'] + "@" + i['version']
            licenses = i['licenses']
            licRS = []
            for r in range(len(licenses)):
                if "id" in licenses[r]['license']:
                    lic = licenses[r]['license']['id']
                elif "name" in licenses[r]['license']:
                    lic = licenses[r]['license']['name']
                else:
                    print("What the ??")
                licRS.append(lic)
            dict = {}
            dict["component"] = component
            dict["licenses"] = licRS
            sCompD.append(dict)

        sVulnRS = sData['vulnerabilities']
        for i in sVulnRS:
            id = i['id']
            targets = i['affects']
            vulnRS = []
            for v in range(len(targets)):
                vuln = targets[v]['ref']
                vuln = vuln.replace("?type=jar", "")
                vuln = vuln.replace("?classifier=exec-war&type=jar", "")
                vulnRS.append(vuln)
            dict = {}
            dict["vulnID"] = id
            dict["targets"] = vulnRS
            sVulnD.append(dict)
        sVulnD = sorted(sVulnD, key=lambda item: item["vulnID"])

        # multiple keys
        sortedlist = sorted(sVulnD , key=lambda elem: "%s %s" % (elem['targets'], elem['vulnID']))
        
        sbomFile.close()


def import_comp_xml():
    global cCompD, cVulnRS, cVulnD

    print("Reading " + competitorSBOM + "... ")
    with open (competitorSBOM, "r") as cbomFile:
        cData = cbomFile.read()
        cBS_data = BeautifulSoup (cData, "xml")
        cBSComps = cBS_data.find('components')
        cBSCompRS = cBSComps.find_all('component')
        for j in cBSCompRS:
            component = j['bom-ref']
            component = component.replace("?type=jar", "")
            licenses = j.find_all('license')
            licRS = []
            for r in range(len(licenses)):
                if licenses[r].find('id'):
                    lic = licenses[r].find('id').text
                elif licenses[r].find("name"):
                    lic = licenses[r].find('name').text
                else:
                    print("What the ??")
                licRS.append(lic)
            dict = {}
            dict["component"] = component
            dict["licenses"] = licRS
            cCompD.append(dict)

        cVulnRS = cBS_data.find_all('vulnerability')
        for j in cVulnRS:
            id = j.find('id').text
#            if id == "sonatype-2014-0015":
#                print ("stop here!!")
            targets = j.find_all('target')
            vulnRS = []
            for v in range(len(targets)):
                vuln = targets[v].find('ref').text
                vuln = vuln.replace("?type=jar", "")
                vulnRS.append(vuln)
            dict = {}
            dict["vulnID"] = id
            dict["targets"] = vulnRS
            cVulnD.append(dict)
        cVulnD = sorted(cVulnD, key=lambda item: item["vulnID"])

        cbomFile.close()


def import_comp_json():
    global cCompD, cVulnRS, cVulnD

    print("Reading " + competitorSBOM + "... ")
    with open (competitorSBOM, "r") as cbomFile:
        cData = json.load(cbomFile)
        cComps = cData['components']
        for j in cComps:
            component = j['name'] + "@" + j['version']
            licenses = j['licenses']
            licRS = []
            for r in range(len(licenses)):
                if "id" in licenses[r]['license']:
                    lic = licenses[r]['license']['id']
                elif "name" in licenses[r]['license']:
                    lic = licenses[r]['license']['name']
                else:
                    print("What the ??")
                licRS.append(lic)
            dict = {}
            dict["component"] = component
            dict["licenses"] = licRS
            cCompD.append(dict)

        if 'vulnerabilites' in cData:
            cVulnRS = cData['vulnerabilities']
            for j in cVulnRS:
                id = j['id']
                targets = j['affects']
                vulnRS = []
                for v in range(len(targets)):
                    vuln = targets[v]['ref']
                    vuln = vuln.replace("?type=jar", "")
                    vuln = vuln.replace("?classifier=exec-war&type=jar", "")
                    vulnRS.append(vuln)
                dict = {}
                dict["vulnID"] = id
                dict["targets"] = vulnRS
                cVulnD.append(dict)
            cVulnD = sorted(cVulnD, key=lambda item: item["vulnID"])

        # multiple keys
        sortedlist = sorted(sVulnD , key=lambda elem: "%s %s" % (elem['targets'], elem['vulnID']))
        
        cbomFile.close()


# Compare the actual components
def compare_components():
    print("\nComparing components found by both tools...")
    for i in range(len(sCompD)):
        found = False
        for j in range(len(cCompD)):
            sCompBomRef = sCompD[i]["component"]
            cCompBomRef = cCompD[j]["component"]

            if sCompBomRef in cCompBomRef or cCompBomRef in sCompBomRef:
                found = True
                comparisonData["componentsFoundByBoth"] += 1

                csvReportFormat.append({
                    "sonaName": sCompBomRef,
                    "sonaCVEs": "", # i["cve"],
                    "sonaPath": "", # i["occurences"],
                    "compName": cCompBomRef,
                    "compCVEs": "", # "j["cve"],
                    "match": str(10),
                })

                break

        if found == False:
            comparisonData["componentMissedByCompetitor"].append(sCompBomRef)

            csvReportFormat.append({
                "sonaName": sCompBomRef,
                "sonaCVEs": "", # "i["cve"],
                "sonaPath": "", # "i["occurences"],
                "compName": "",
                "compCVEs": "",
                "match": "",
            })

    for j in range(len(cCompD)):
        found = False
        for i in range(len(sCompD)):
            sCompBomRef = sCompD[i]["component"]
            cCompBomRef = cCompD[j]["component"]

            if sCompBomRef in cCompBomRef or cCompBomRef in sCompBomRef:
                found = True
                break

        if found == False and cCompBomRef not in comparisonData["additionalCompetitorComponents"]:
            comparisonData["additionalCompetitorComponents"].append(cCompBomRef)
            csvReportFormat.append({
                "sonaName": "",
                "sonaCVEs": "",
                "sonaPath": "",
                "compName": cCompBomRef,
                "compCVEs": "", # "i["cve"],
                "match": "",
            })


    comparisonData["componentMissedByCompetitor"].sort()
    comparisonData["componentMissedByCompetitorLength"] = len(comparisonData["componentMissedByCompetitor"])
    comparisonData["additionalCompetitorComponents"].sort()
    comparisonData["additionalCompetitorComponentsLength"] = len(comparisonData["additionalCompetitorComponents"])

    print("Sonatype found ", comparisonData["componentMissedByCompetitorLength"],
          " components not found by the compeitor.")
    print("The competitor found ", comparisonData["additionalCompetitorComponentsLength"], " not found by Sonatype.")


# Compare licenses
def compare_licenses():
    print("\nComparing component licesnses...")

    for i in range(len(sCompD)):
        sCompBomRef = sCompD[i]["component"]
        sona_lics = sCompD[i]["licenses"]
        same = True

        for j in range(len(cCompD)):
            cCompBomRef = cCompD[j]["component"]
            comp_lics = cCompD[j]["licenses"]
            
            if sCompBomRef in cCompBomRef or cCompBomRef in sCompBomRef:
                if len(sona_lics) != len(comp_lics):
#                    print("Different lengths")
                    same = False
                    discrep = {
                        "Component": sCompBomRef,
                        "Found By Sonatype": sona_lics,
                        "Found By Competitor": comp_lics
                    }
                    comparisonData["licensingDiscrepencies"].append(discrep)
                else:
                    for k in range(len(sona_lics)):
                        if sona_lics[k] not in comp_lics:
                            same = False
                    if same == False:
                        discrep = {
                            "Component": sCompBomRef,
                            "Found By Sonatype": sona_lics,
                            "Found By Competitor": comp_lics
                        }
                        comparisonData["licensingDiscrepencies"].append(discrep)
            else:
                continue

    comparisonData["licensingDiscrepenciesLength"] = len(comparisonData["licensingDiscrepencies"])


# Compare CVEs
def compare_cves():
    print("\nComparing component CVEs...")

    # Iterate through Sonatype data
    for i in range(len(sVulnD)):
        sVulnID = sVulnD[i]["vulnID"]
#        if sVulnID == "sonatype-2014-0015":
#            print ("stop here!!")
        sona_targets = sVulnD[i]["targets"]
        same = True
        found = False

        for j in range(len(cVulnD)):
            cVulnID = cVulnD[j]["vulnID"]
#            if cVulnID == "sonatype-2014-0015":
#                print ("stop here!!")
            comp_targets = cVulnD[j]["targets"]

            if sVulnID in cVulnID or cVulnID in sVulnID:
                found = True
                if len(sona_targets) != len(comp_targets):
                    same = False
                    discrep = {
                        "Vulnerability": sVulnID,
                        "Found by Sonatype": sona_targets,
                        "Found by Competitor": comp_targets
                    }
                    comparisonData["cveDiscrepencies"].append(discrep)
                else:
                    for k in range(len(sona_targets)):
                        if sona_targets[k] not in comp_targets:
                            same= False
                    if same == True:
                        comparisonData["cveFoundByBoth"] += 1
                    else:
                        discrep = {
                            "Vulnerability": sVulnID,
                            "Found by Sonatype": sona_targets,
                            "Found by Competitor": comp_targets
                            }
                        comparisonData["cveDiscrepencies"].append(discrep)
            else:
                continue
        if found == False:
            comparisonData["cveMissingCompetitor"].append(sVulnID + " - " + str(sona_targets))

    comparisonData["cveMissingCompetitorLength"] = len(comparisonData["cveMissingCompetitor"])
                
    # Iterate through competitor data and repeat above
    for j in range(len(cVulnD)):
        cVulnID = cVulnD[j]["vulnID"]
#        if cVulnID == "sonatype-2014-0015":
#            print ("stop here!!")
        comp_targets = cVulnD[j]["targets"]
        found = False

        for i in range(len(sVulnD)):
            sVulnID = sVulnD[i]["vulnID"]
#            if sVulnID == "sonatype-2014-0015":
#                print ("stop here!!")

            if cVulnID in sVulnID or sVulnID in cVulnID:
                found = True
            else:
                continue
        if found == False:
            comparisonData["additionalCompetitorCVEs"].append(cVulnID + " - " + str(comp_targets))

    comparisonData["additionalCompetitorCVEsLength"] = len(comparisonData["additionalCompetitorCVEs"])
    comparisonData["cvdDiscrepenciesLength"] = len(comparisonData["cveDiscrepencies"])


def get_10_worst_components_missed_by_competitor():
    print("Getting 10 worst components missed by competitor...")

    worst = []
    for i in csvReportFormat:
        # If it's not found by competitor
        if (i["match"] == "" and
                i["match"] != "Confidence" and
                len(i["sonaName"]) > 1 and
                len(i["sonaCVEs"]) > 0):
            for j in sonatypeData:
                if i["sonaName"] == j["component"]:
                    score = 0.0
                    for k in j["cveSeverities"]:
                        arr = k.split(" : ")
                        score += float(arr[1])

                    worst.append({
                        "score": score,
                        "component": i["sonaName"],
                        "cves": j["cveSeverities"]
                    })

    worst.sort(key=lambda x: x["score"], reverse=True)
    worst = worst[0:9]
    comparisonData["10WorstCompontnentsMissedByCompetitor"] = worst


def get_licensing_issues_missed_by_competitor():
    print("Getting license issues missed in components missed by competitor...")
    licIssues = []
    for i in csvReportFormat:
        # If it's not found by competitor
        if (i["match"] == "" and
                i["match"] != "Confidence" and
                len(i["sonaName"]) > 1):
            for j in sonatypeData:
                if i["sonaName"] == j["component"]:
                    if j["licenseThreats"] != []:

# This puts the licenses with their threat group
#                        licParts=[]
#                        for k in range(len(j["licenseThreats"])):
#                            licParts.append(str(j["licenseThreats"][k]) + " : " + str(j["licensePlus"][k]))
#                       licIssues.append(str(licParts) + " : " + j["component"])
 
 # This puts the threat groups together
                        licIssues.append(
                            str(j["licenseThreats"]) + " : " + str(j["licensePlus"]) + " : " + j["component"])

    comparisonData["badLicenseInComponentsMissedByCompetitor"] = licIssues
    comparisonData["badLicenseInComponentsMissedByCompetitorLength"] = len(licIssues)


def format_csv_report():
    # Write to CSV file
    csvReport = []
    header = []

    for i in csvReportFormat:
        if len(header) > 0:
            csvReport.append([
                i["compName"],
                ", ".join(str(x) for x in i["compCVEs"]),
                i["match"],
                i["sonaName"],
                ", ".join(str(x) for x in i["sonaCVEs"])
            ])
        else:
            header = [
                i["compName"] + " (" + str(comparisonData["uniqueComponentsFoundByCompetitor"]) + ")",
                i["compCVEs"],
                i["match"],
                i["sonaName"] + " (" + str(comparisonData["uniqueComponentsFoundBySonatype"]) + ")",
                i["sonaCVEs"]
            ]

    # Sort by match confidence and then name
    csvReport.sort(key=lambda row: (-1 * int(row[2] or 0), row[3], row[0]), reverse=False)
    csvReport[:0] = [header]

    with open(csvOutputFile, "w+") as my_csv:
        csvWriter = csv.writer(my_csv, delimiter=',')
        csvWriter.writerows(csvReport)

    print("CSV report written to '" + csvOutputFile + "'...")


# ==========================
# ========== MAIN ==========
# ==========================

def main(e):
    # compareData
    print("\n- INITIATING DATA COMPARISON - ")
    global competitorSBOM, sonatypeSBOM
    competitorSBOM = e["competitorSBOM"]
    sonatypeSBOM = e["sonatypeSBOM"]

    import_reports()
    compare_components()

    if comparisonData["componentsFoundByBoth"] == 0:
        print("\nOOPS!!!")
        print(
            "We found NO (0) component matches! This means that something is wrong with the component naming convention.")
        print(
            "Look at the csv-data-comparison.csv to see how components are named and make sure the competitor file is naming the same way!")

        # Write to file
        f = open(jsonOutputFile, "w")
        f.write(json.dumps(comparisonData))
        f.close()
        print("\nCheck the '" + jsonOutputFile + "' for more details...")

        quit()

    compare_cves()
    compare_licenses ()
#    get_10_worst_components_missed_by_competitor()
#    get_licensing_issues_missed_by_competitor()

    # Write to file
    f = open(jsonOutputFile, "w")
    f.write(json.dumps(comparisonData))
    f.close()
    print("\nResults written to '" + jsonOutputFile + "'...")

    format_csv_report()  # Print report in CSV format


if __name__ == "__main__":
    main({
        "competitorSBOM": competitorSBOM,
        "sonatypeSBOM": sonatypeSBOM,
        "csvOutputFile": csvOutputFile,
        "jsonOutputFile": jsonOutputFile
        })
