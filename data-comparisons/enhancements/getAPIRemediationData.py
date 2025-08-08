#!/usr/bin/env python
import json
import requests
import settings

# ========= ENVIRONMENT VARIABLES ========
# applicationID = "Struts2-rce"
# url = "http://localhost:8070/" #URL including trailing '/'
# username = "admin"
# password = "admin!23"
# stage = "build" # *, develop, source, build, stage-release, release 
#Configure the functions in the settings.py to determine what data to get
# =============================================

#Default variables
global fullReportData
global licenseData
global cycloneData

fullReportData = []
licenseData = {}
cycloneData = ""

def __parse_license_data(license_data):
    """ The legal data response includes a 'licenseLegalData' section that maps a license to a threat group, in addition to providing other metadata about that license."""
    result = {}
    if license_data is None:
        return result

    for license in license_data:
        # Exclude multi-licenses here as a multi-license is really composed of individual single licenses.
        if license['isMulti'] == False:
            threat = {}
            threat['name'] = license['threatGroup']['name']
            threat['level'] = license['threatGroup']['threatLevel']
            result[license['licenseId']] = threat

    return result

def __parse_multi_license_data(license_data):
    """ The 'licenseLegalData' section of the response also maps multi-licenses to their individual single licenses, which we need to parse if we want to obtain the license threat group for those single licenses."""
    result = {}
    if license_data is None:
        return result

    for license in license_data:
        if license['isMulti'] == True:
            result[license['licenseId']] = license['singleLicenseIds']

    return result


def __parse_component_data(license_data, multi_license_data, components):
    """Using the provided license and multi-license data, map each component's licenses to their respective threat groups."""
    result = []
    if components is None:
        return result

    for component in components:
        component_identifier_json = json.dumps(component['componentIdentifier'])
        component_display_name = component['displayName']
        effective_licenses = component['licenseLegalData']['effectiveLicenses']
        effective_threat_groups = set()
        highest_effective_threat_group = ''

        if component['licenseLegalData']['highestEffectiveLicenseThreatGroup'] is not None:
            highest_effective_threat_group = component['licenseLegalData']['highestEffectiveLicenseThreatGroup'][
                'licenseThreatGroupName']

        # This looks strange, but what we're doing here is first checking to see if it is a single license
        # by looking at the license_data mapping. If it isn't a single license then we use the multi-license
        # mapping to convert the multi-license into an array of single licenses, which we then map using
        # the license data mapping.
        for effective_license in effective_licenses:
            if effective_license in license_data:
                effective_threat_groups.add(license_data[effective_license])
            elif effective_license in multi_license_data:
                for single_license in multi_license_data[effective_license]:
                    if single_license in license_data:
                        effective_threat_groups.add(license_data[single_license])

        result.append([component_identifier_json, component_display_name, ', '.join(effective_licenses),
                       ', '.join(effective_threat_groups),
                       highest_effective_threat_group])

    return result


def get_report_data():
    global applicationID, url, username, password, stage, cycloneData

    print("Getting ",applicationID," Reports...")
    # ref: https://help.sonatype.com/iqserver/automating/rest-apis/application-rest-apis---v2

    url = url+"api/v2/"

    # fetch report from uri
    sendurl = url+"applications?publicId="+applicationID
    res = requests.get(sendurl, auth=(username, password)) #, timeout=120
    # Load result string to json
    print(res.text)
    json_data = json.loads(res.text) #Get internal app ID for input
    
    global internalAppID
    internalAppID = json_data['applications'][0]['id'] #Select first internal app ID

    sendurl = url+"cycloneDx/1.4/" + internalAppID + "/stages/" + stage
    res = requests.get(sendurl, auth=(username, password)) #, timeout=120
#    print(res.text)
    cycloneData = res.text

    sendurl = url+"reports/applications/"+internalAppID
    res = requests.get(sendurl, auth=(username, password))
    json_data = json.loads(res.text)
    # print(json_data) #Info for latest reports for each stage

    #Loop all reports 
    for item in json_data:
        if stage == "*" or item['stage'] == stage: #Only select desired stage(s)
            reportID = item['reportDataUrl'] 
            reportID = reportID.replace('api/v2/', '')
            # print(reportID)
            sendurl = url+reportID
            res = requests.get(sendurl, auth=(username, password))
            json_data = json.loads(res.text)
            json_data = json_data['components']
            newComponents = clean_duplicate_components(json_data)
            fullReportData.extend(newComponents)

    # get the license data
    result = {}
    sendurl = url+"licenseLegalMetadata/application/"+internalAppID
    res = requests.get(sendurl, auth=(username, password))
    legal_data = json.loads(res.text)
    license_data = __parse_license_data(legal_data['licenseLegalMetadata'])
    multi_license_data = __parse_multi_license_data(legal_data['licenseLegalMetadata'])
#    component_data = __parse_component_data(license_data, multi_license_data, legal_data['components'])
    licenseData['licenseSingleLegalMeta'] = license_data
    licenseData['licenseMultiLegalMeta'] = multi_license_data
    print('End of processing legal')
#    licenseData['licenseLegalMetter'] = license_data
#    fullReportData.append(license_data)

   # print(fullReportData)
    

def clean_duplicate_components(newItems):
    print("Clean duplicate components...")
    returnList = []
    for i in newItems:
        found = False
        for j in fullReportData:
            if i['hash'] == j['hash']:
                found = True
        if found == False:
            returnList.append(i)

    return returnList


def get_version_remediation_data():
    print("Getting Remediation Data for ",len(fullReportData)," Components...")
    # ref: https://help.sonatype.com/iqserver/automating/rest-apis/component-remediation-rest-api---v2

    for i in range(len(fullReportData)):

        sendurl = url+"components/remediation/application/"+internalAppID
        if stage != "*":
            sendurl = sendurl +"?stageId="+stage
        
        print(fullReportData[i]["componentIdentifier"])
        payload = json.dumps({"componentIdentifier":fullReportData[i]["componentIdentifier"]})
        if payload == None:
            payload =  json.dumps({"packageUrl":fullReportData[i]["packageUrl"]}) #Sometimes returns None

        headers = {
            'Content-Type': 'application/json'
        }

        try:
            res = requests.post(
                sendurl, 
                auth=(username, password), 
                headers=headers,
                data=payload)
            try:
                json_data = json.loads(res.text)
                fullReportData[i]["remediation"] = json_data["remediation"]
            except:
                fullReportData[i]["remediation"] = res.text +" Usually this is a proprietary component."
        except:
            pass


def get_CVE_details():
    print("Getting CVE Data for ",len(fullReportData)," Components...")
    # ref: https://help.sonatype.com/iqserver/automating/rest-apis/vulnerability-details-rest-api---v2

    for i in range(len(fullReportData)):
        if fullReportData[i]["securityData"] != None:
            if len(fullReportData[i]["securityData"]["securityIssues"]) >0:
                for j in range(len(fullReportData[i]["securityData"]["securityIssues"])):
                    cve = fullReportData[i]["securityData"]["securityIssues"][j]['reference']
                    print(cve+'...')
                    sendurl = url+"vulnerabilities/"+cve
                    res = requests.get(sendurl, auth=(username, password))
                    try:
                        json_data = json.loads(res.text)
                        fullReportData[i]["securityData"]["securityIssues"][j]['deeperData'] = json_data
                    except:
                        fullReportData[i]["securityData"]["securityIssues"][j]['deeperData'] = res.text

    print("Completed getting deeper vulnerability data...")


# def get_policy_data():
    # ref: https://help.sonatype.com/iqserver/automating/rest-apis/policy-violation-rest-api---v2
    # print("Getting Policy Violation Data...")


def main(e):
    print("\n- GETTING SONATYPE DATA - ")
    global applicationID, url, username, password, stage

    applicationID = e["applicationID"]
    url = e["url"]
    username = e["username"]
    password = e["password"]
    stage = e["stage"]
    sonatypeSBOM = e["sonatypeSBOM"]
    sonatypeLicsFile = e["sonatypeLicsFile"]

    #getAPIRemediationData()
    get_report_data() #Get SBOM data
    get_version_remediation_data() 
    get_CVE_details()

    #Write to file
    f = open(sonatypeSBOM, "w")
    f.write(json.dumps(fullReportData))
    f.close()
    print("Results written to "+sonatypeSBOM+"\'")

    # after doing this add the legal stuff
    #Write to file
    f = open(sonatypeLicsFile, "w")
    f.write(json.dumps(licenseData))
    f.close()
    print("Results written to "+sonatypeLicsFile+"\'")

    f = open("processedFiles/cycloneDX-" + settings.appShort + ".xml", "w")
    f.write(cycloneData)
    f.close()
    print("Results written to " +"processedFiles/cycloneDX-" + settings.appShort + ".xml" +"\'")


#==========================
#========== MAIN ==========
#==========================
# if __name__ == "__main__":
    # main(apiEnv)