#!/usr/bin/env python
import json
import csv
import math

# ========= ENVIRONMENT VARIABLES ========
competitorSBOM = ""
sonatypeSBOM = ""
masterLicsFile = ""
csvOutputFile = ""
jsonOutputFile = ""
checkLicenses = True  # Do a license comparison?
# =============================================

# global sonatypeData
sonatypeData = []
# global masterLicData
masterLicData = {}
# global competitorData
competitorData = []

# global comparisonData
comparisonData = {
    "componentsFoundByBoth": 0,
    "uniqueComponentsFoundBySonatype": 0,
    "uniqueComponentsFoundByCompetitor": 0,
    "componentMissedByCompetitor": [],
    "componentMissedByCompetitorLength": 0,
    "additionalCompetitorComponents": [],
    "additionalCompetitorComponentsLength": 0,
    "potentialMatches": [],
    "potentialMatchesLength": 0,
    "cveFoundByBoth": 0,
    "cveMissingCompetitor": [],
    "cveMissingCompetitorLength": 0,
    "additionalCompetitorCVEs": [],
    "additionalCompetitorCVEsLength": 0,
    "sonatypeFoundLaterUpdatedCVEs": [],
    "10WorstCompontnentsMissedByCompetitor": [],  # Top 10 worst components missed by competitor
    "badLicenseInComponentsMissedByCompetitor": [],  # Components missed by competitor with bad license
    "badLicenseInComponentsMissedByCompetitorLength": 0
}

if checkLicenses == True:
    comparisonData["licensingDiscrepencies"] = []
    comparisonData["licensingDiscrepenciesCount"] = 0

csvReportFormat = [
    {
        "sonaName": "Sonatype Component Name",
        "sonaCVEs": "Sonatype CVEs",
        # "sonaLic": "Sonatype Licenses",
        "sonaPath": "Sonatype Occurence Path",
        "compName": "Competitor Component Name",
        "compCVEs": "Competitor CVEs",
        # "compLic": "Competitor Licenses",
        "match": "Confidence",
    }
]


# Read both SBOMs
def import_reports():
    print("Reading " + masterLicsFile + "... ")
    f = open(masterLicsFile, "r")
    masterLicData = json.load(f)

    print("Reading " + sonatypeSBOM + "... ")
    f = open(sonatypeSBOM, "r")
    jsonData = json.load(f)

    global sonatypeData
    for i in jsonData:
        if i["securityData"] != None:
            # Get the CVEs
            # sort CVEs by severity
            cveReturn = get_CVEs(i["securityData"]["securityIssues"])
            cves = cveReturn["cves"]
            severities = cveReturn["severities"]

            # Get licenses
            licData = get_licence_array(i["licenseData"], masterLicData)
            lics = licData["lics"]
            licsPlus = licData['licsPlus']
            licThreats = licData["threats"]

            # Get component name
            compName = i["displayName"]
            if ":" not in compName:
                compName = compName.replace(" ", ":")
            compName = compName.replace(" ", "")

            # Get best occurence
            occurence = get_best_occurence(i)

            sonatypeData.append({
                "component": compName,
                "licenses": lics,
                "licensePlus": licsPlus,
                "cve": cves,
                "cveSeverities": severities,
                "licenseThreats": licThreats,
                "occurences": occurence
            })
    f.close()

    sonatypeData = consolidate_components(sonatypeData)
    comparisonData["uniqueComponentsFoundBySonatype"] = len(sonatypeData)

    global competitorData
    competitorData = read_competitor_sbom()
    competitorData = consolidate_components(competitorData)
    comparisonData["uniqueComponentsFoundByCompetitor"] = len(competitorData)


# Parse competitor data file
def read_competitor_sbom():
    print("Reading " + competitorSBOM + "... ")
    f = open(competitorSBOM, "r")

    returnData = []

    # If file is .csv
    if competitorSBOM.endswith(".csv"):
        precols = {
            "name": None,
            "lic": None,
            "cve": None,
            "sev": "N/A"
        }
        cols = {}
        indexSet = False

        csvData = csv.reader(f)
        for lines in csvData:

            # Determine value columns
            if indexSet == False:
                cols = get_column_indicies(precols, lines)
                indexSet = True

            else:
                dataObj = {"component": lines[cols["name"]].replace(" ", ""), "licenses": [], "cve": []}

                if checkLicenses == True:
                    if (len(lines[cols["lic"]]) > 3):
                        dataObj["licenses"] = [lines[cols["lic"]]]  # Check license length

                if (len(lines[cols["cve"]]) > 3):
                    parts = lines[cols["cve"]].split(";")
                    partsLen = len(parts)
                    for partIndex in range(partsLen):
                        parts[partIndex] = parts[partIndex].strip()
                    dataObj["cve"] = parts
                #                    dataObj["cve"] = [lines[cols["cve"]]] #Check CVE length

                returnData.append(dataObj)


    # If file is .json
    elif competitorSBOM.endswith(".json"):
        jsonData = json.load(f)
        for i in jsonData["components"]:
            data = {
                "component": "",
                "licenses": [],
                "cve": []
            }

            # Use the package url
            if "purl" in i:
                name = i["purl"].split("/")
                del name[0]
                name = ':'.join(name)
                data["component"] = name.replace("@", ":")
            else:
                name = i["name"] + ":" + i["version"]
                data["component"] = name.replace(" ", "")
                data["component"] = data["component"].replace("%40", "@")
                if data["component"][0] == "@":
                    data["component"] = data["component"].replace(":", "/", 1)

            if "cve" in i:
                # print("FIX: FIND THE CVE")
                cves = i["cve"]
                # for j in i["securityData"]["securityIssues"]:
                #     cves.append(j["reference"])

                data["cve"] = cves

            licenses = []
            for j in i["licenses"]:
                if "id" in j["license"]:
                    licenses.append(j["license"]["id"])
                else:
                    licenses.append(j["license"]["name"])

            data["licenses"] = licenses

            returnData.append(data)

    else:
        print("ERROR COMPETITOR SBOM ", competitorSBOM, " NOT COMPATIBLE!")
        quit()

    return returnData


def get_column_indicies(cols, lines):
    print("\tFound column headers: ")
    for i in range(len(lines)):
        item = lines[i].lower()
        print("\t\t- " + item)
        if "components" == item or "component" == item:
            cols["name"] = i
        if "licenses" == item or "license" == item:
            cols["lic"] = i
        if "cves" == item or "cve" == item:
            cols["cve"] = i
        # if "severity" == item:
        #     cols["sev"] = i

    for i in cols:
        if cols[i] == None:
            if (i == "lic" and checkLicenses == True) or i != "lic":
                colTitles = {
                    "name": "Component",
                    "lic": "License",
                    "cve": "CVE",
                    "sev": "Severity"
                }
                print("\nERROR: Could not identify column header: **" + colTitles[i] + "**")
                print("Please make sure columns exist and are correctly labeled with Component, License, or CVEs. \n")
                quit()
    return cols


# Get CVE data
def get_CVEs(e):
    # e = i["securityData"]["securityIssues"]
    cves = []
    severities = []
    for j in e:
        cves.append(j["reference"])
        severities.append(j["reference"] + " : " + str(j["severity"]))

        # Append Multiple CVEs
        if "deeperData" in j:
            try:
                multipleCVEs = j["deeperData"]["vulnIds"]
                multipleCVEs.remove(j["reference"])

                if len(multipleCVEs) > 0:
                    # print(multipleCVEs)
                    for k in multipleCVEs:
                        cves.append(k)
                        severities.append(k + " : " + str(j["severity"]))
                        comparisonData["sonatypeFoundLaterUpdatedCVEs"].append(j["reference"] + " -> " + k)
            except:
                pass

    return {
        "cves": cves,
        "severities": severities
    }


# Get occurences data
def get_best_occurence(e):
    name = e["componentIdentifier"]["coordinates"]
    if "artifactId" in name:
        name = name["artifactId"]
    elif "packageId" in name:
        name = name["packageId"]
    elif "name" in name:
        name = name["name"]
    else:
        print("NO ID: ", e["displayName"])

    occurence = ""
    for o in e["pathnames"]:
        if (name in o
                and "ignore" not in o
                and ".md" not in o
                and "LICENSE" not in o
                and "CHANGELOG" not in o
                and ".yml" not in o):
            occurence = o
            break

    if occurence == "":
        for o in e["pathnames"]:
            if ("ignore" not in o
                    and ".md" not in o
                    and "LICENSE" not in o
                    and "CHANGELOG" not in o
                    and ".yml" not in o):
                occurence = o
                break

    if occurence == "":
        occurence = e["pathnames"][0]
        # print(e["displayName"])

    return occurence


# Turn license JSON into array
def get_licence_array(e, masterLicData):
    licenses = []
    licTypes = []
    for i in e["declaredLicenses"]:
        licenses.append(i["licenseId"])
        licTypes.append("D")

    for i in e["observedLicenses"]:
        licenses.append(i["licenseId"])
        licTypes.append("O")

    for i in e["effectiveLicenses"]:
        licenses.append(i["licenseId"])
        licTypes.append("E")

    returnLics = []
    tempTypes = []
    threatsGN = []
    for i in range(len(licenses)):
        lic = licenses[i]
        type = licTypes[i]
        if lic not in returnLics:
            if lic in masterLicData['licenseSingleLegalMeta']:
                if masterLicData['licenseSingleLegalMeta'][lic]['level'] >= 2:
                    if type != "D":
                        print("Not a declared license")

                    returnLics.append(lic)
                    tempTypes.append(type)
                    threatsGN.append(masterLicData['licenseSingleLegalMeta'][lic]['name'])

    licsPlus = []

    for i in range(len(returnLics)):
        lic = returnLics[i]
        type = tempTypes[i]
        licsPlus.append(lic + "_" + type)
    #        threatsGN.append(tempThreat[i])

    returnData = {
        "lics": returnLics,
        "licsPlus": licsPlus,
        "threats": threatsGN
    }

    return returnData


# Sort unique components
def consolidate_components(e):
    unique = []

    for i in e:
        found = False
        for j in range(len(unique)):
            if i["component"] in unique[j]["component"]:
                found = True
                for k in i["cve"]:
                    if k not in unique[j]["cve"]:
                        unique[j]["cve"].append(k)

        if found == False:
            unique.append(i)

    # Clean up data
    for i in unique:
        # Remove blank CVEs
        if i["cve"] == [""]:
            i["cve"] = []

    print("\t Found ", len(unique), " unique components")
    return unique


# Compare the actual components
def compare_components():
    print("\nComparing components found by both tools...")
    for i in sonatypeData:
        found = False
        for j in competitorData:
            #            if "springframework" in i["component"] and "springframework" in j["component"]:
            #                print("Stop here!!")

            if i["component"] in j["component"] or j["component"] in i["component"]:
                found = True
                comparisonData["componentsFoundByBoth"] += 1

                csvReportFormat.append({
                    "sonaName": i["component"],
                    "sonaCVEs": i["cve"],
                    "sonaPath": i["occurences"],
                    "compName": j["component"],
                    "compCVEs": j["cve"],
                    "match": str(10),
                })

                if checkLicenses == True:
                    compare_licenses(i, j)

                break

        if found == False:
            comparisonData["componentMissedByCompetitor"].append(i["component"])

            csvReportFormat.append({
                "sonaName": i["component"],
                "sonaCVEs": i["cve"],
                "sonaPath": i["occurences"],
                "compName": "",
                "compCVEs": "",
                "match": "",
            })

    for i in competitorData:
        found = False
        for j in sonatypeData:
 #           if j['component'].startswith("lodash"):
 #               print("Stop here!!")
            if i["component"] in j["component"] or j["component"] in i["component"]:
                found = True
                break

        if found == False and i["component"] not in comparisonData["additionalCompetitorComponents"]:
            comparisonData["additionalCompetitorComponents"].append(i["component"])
            csvReportFormat.append({
                "sonaName": "",
                "sonaCVEs": "",
                "sonaPath": "",
                "compName": i["component"],
                "compCVEs": i["cve"],
                "match": "",
            })

            # "additionalCompetitorComponents"
            # "componentMissedByCompetitor"

    comparisonData["componentMissedByCompetitor"].sort()
    comparisonData["componentMissedByCompetitorLength"] = len(comparisonData["componentMissedByCompetitor"])
    comparisonData["additionalCompetitorComponents"].sort()
    comparisonData["additionalCompetitorComponentsLength"] = len(comparisonData["additionalCompetitorComponents"])

    print("Sonatype found ", comparisonData["componentMissedByCompetitorLength"],
          " components not found by the compeitor.")
    print("The competitor found ", comparisonData["additionalCompetitorComponentsLength"], " not found by Sonatype.")

    if checkLicenses == True:
        comparisonData["licensingDiscrepenciesCount"] = len(comparisonData["licensingDiscrepencies"])
        print("Found ", comparisonData["licensingDiscrepenciesCount"], " license discrepencies.")


# Partial match components
def fuzzy_match_components():
    print("\nChecking if exact match didn't quite do it...")

    compMissing = comparisonData["additionalCompetitorComponents"]  # comparisonData["componentMissedByCompetitor"]
    # sonaMissing = comparisonData["additionalCompetitorComponents"]

    # fuzzyMatching = ["Confidence Level : Sonatype Component ~= Competitor Component"]
    fuzzyMatching = []
    found = False
    level9 = 0
    for i in compMissing:
        # Get levels
        for s in reversed(range(10)):

            if s > 1 and found == False:
                matching = math.floor(len(i) - (len(i) / s))
                substring = i[0:matching]
                # print(matching," < ", len(i))

                # level = []
                for item in sonatypeData:
                    j = item["component"]
                    if i != j:
                        if substring in j:
                            dataObj = {
                                "level": s,
                                "comp": i,
                                "sona": j,
                                "sonatype-location": item["occurences"]
                            }
                            fuzzyMatching.append(dataObj)

                            # fuzzyMatching.append("LEVEL "+str(s)+" - "+i+" ~= "+j)
                            if s > 8:
                                level9 += 1

                            # Remove duplicate component from list
                            csvRow = ""
                            compCVEstr = ""
                            k = 0
                            while k < len(csvReportFormat):
                                if i == csvReportFormat[k]["compName"]:
                                    compCVEstr = csvReportFormat[k]["compCVEs"]
                                    del (csvReportFormat[k])
                                elif j == csvReportFormat[k]["sonaName"] and csvReportFormat[k]["match"] == "":
                                    del (csvReportFormat[k])
                                else:
                                    k = k + 1

                            # Replace with partially matched
                            csvReportFormat.append({
                                "sonaName": j,
                                "sonaCVEs": item["cve"],
                                "sonaPath": item["occurences"],
                                "compName": i,
                                "compCVEs": compCVEstr,
                                "match": str(s),
                            })

                            found = True
                            break

        found = False

    # Clean up duplicates from fuzzy matched going from highest score to lowest
    comparisonData["potentialMatches"] = fuzzyMatching  # = sorted(fuzzyMatching)
    comparisonData["potentialMatchesLength"] = len(fuzzyMatching)
    print("With similar matching, we found ", len(fuzzyMatching), "(", str(level9),
          " high confidence) potential matches.")


# Add occurences to output
def add_occurences_to_sonatype_data():
    print("\nAdding occurrences to Sonatype found components...")
    for i in range(len(comparisonData["componentMissedByCompetitor"])):
        for j in sonatypeData:
            if comparisonData["componentMissedByCompetitor"][i] == j["component"]:
                comparisonData["componentMissedByCompetitor"][i] += " -> LOCATION:\'" + j["occurences"] + "\'" + " -> #CVEs:" + str(len(j["cve"]))


# Compare licenses
def compare_licenses(sona, comp):
    # print("\nComparing component licesnses...")

    same = True
    for sona_lic in sona["licenses"]:
        # sona_lic = sona_lic.replace("+", "")
        if sona_lic not in comp["licenses"]:
            same = False

    for comp_lic in comp["licenses"]:
        # comp_lic = comp_lic.replace("+", "")
        if comp_lic not in sona["licenses"]:
            same = False

    if same == False:
        discreps = {
            "Component": sona["component"],
            "FoundBySonatype": sona["licensePlus"],
            "FoundByCompetitor": comp["licenses"]
        }
        comparisonData["licensingDiscrepencies"].append(discreps)


# Compare CVEs
def compare_cves():
    print("\nComparing component CVEs...")

    # Iterate through Sonatype data
    for sona in sonatypeData:
        # Iterate through Sonatype CVEs
        for sona_cve in sona["cve"]:
            found = False

            # Iterate through competitor data
            for comp in competitorData:
                # Check if it is a regular CVE
                if "CVE-" in sona_cve:
                    # Check if Sonatype CVE in competitor list
                    if sona_cve in comp["cve"]:
                        found = True
                        comparisonData["cveFoundByBoth"] += 1

                # Check if Sonatype CVE matches any of theirs
                elif "CVE-" not in sona_cve and sona["component"] in comp["component"]:

                    compCVEs = []
                    for c in comp["cve"]:
                        if "CVE-" not in c:
                            compCVEs.append(c)

                    if len(compCVEs) > 0:
                        sona_cve = sona_cve + " ~> " + str(compCVEs)

            # If the CVE is never found add it to the missing list
            if found == False:
                comparisonData["cveMissingCompetitor"].append(sona_cve + " - " + sona["component"])

    comparisonData["cveMissingCompetitorLength"] = len(comparisonData["cveMissingCompetitor"])

    # Iterate through competitor data and repeat above
    uniqueCVECount = {}
    for comp in competitorData:
        for comp_cve in comp["cve"]:
            found = False
            for sona in sonatypeData:
                if comp_cve in sona["cve"]:
                    found = True

            if found == False:
                comparisonData["additionalCompetitorCVEs"].append(comp_cve + ", " + comp["component"])

                if comp_cve in uniqueCVECount:
                    uniqueCVECount[comp_cve] += 1
                else:
                    uniqueCVECount[comp_cve] = 1

    # Append repetition to competitor results
    for i in range(len(comparisonData["additionalCompetitorCVEs"])):
        for key in uniqueCVECount:
            if key in comparisonData["additionalCompetitorCVEs"][i]:
                repl = key + ", (" + str(uniqueCVECount[key]) + ")"
                comparisonData["additionalCompetitorCVEs"][i] = comparisonData["additionalCompetitorCVEs"][i].replace(
                    key, repl)
                break

    # print(comparisonData["additionalCompetitorCVEs"])

    comparisonData["additionalCompetitorCVEsLength"] = len(comparisonData["additionalCompetitorCVEs"])


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
                ", ".join(str(x) for x in i["sonaCVEs"]),
                i["sonaPath"]
            ])
        else:
            header = [
                i["compName"] + " (" + str(comparisonData["uniqueComponentsFoundByCompetitor"]) + ")",
                i["compCVEs"],
                i["match"],
                i["sonaName"] + " (" + str(comparisonData["uniqueComponentsFoundBySonatype"]) + ")",
                i["sonaCVEs"],
                i["sonaPath"]
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
    global competitorSBOM, sonatypeSBOM, masterLicsFile, csvOutputFile, jsonOutputFile, checkLicenses
    competitorSBOM = e["competitorSBOM"]
    sonatypeSBOM = e["sonatypeSBOM"]
    masterLicsFile = e["masterLicsFile"]
    csvOutputFile = e["csvOutputFile"]
    jsonOutputFile = e["jsonOutputFile"]

    checkLicenses = e["checkLicenses"]

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

    fuzzy_match_components()
    add_occurences_to_sonatype_data()
    compare_cves()
    get_10_worst_components_missed_by_competitor()
    get_licensing_issues_missed_by_competitor()

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
        "masterLicsFile": masterLicsFile,
        "csvOutputFile": csvOutputFile,
        "jsonOutputFile": jsonOutputFile,
        "checkLicenses": False
    })
