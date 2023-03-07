#!/usr/bin/env python

import json
import requests
import subprocess
from pprint import pprint
import os
from urllib.parse import urlparse


# REQUIREMENTS:
#   1. Update all the environment variables below 
#   2. Turn on automatic applications in IQ
#   3. In IQ create an Organization, and copy the organization ID
#      into the iq_organization_id field. Ex: https://help.sonatype.com/iqserver/integrations/nexus-iq-cli#NexusIQCLI-organizationLocatingtheorganizationID


# Environment Variables
iq_app_name_prefix = "Raw-Hosted-NXRM"
iq_organization_id = "5a539d42a7734557a93583950010d4f8" #https://help.sonatype.com/iqserver/integrations/nexus-iq-cli#NexusIQCLI-organizationLocatingtheorganizationID

nxrm_url = "http://localhost:8081" #NOT include trailing '/'
nxrm3_username = "admin"
nxrm3_password = "admin!23"
repo_name = "raw-hosted"

iq_url = "http://localhost:8070" #NOT include trailing '/'
iq_username = "admin"
iq_password = "admin!23"
iq_phase = "release"
path_to_cli_jar = '/Users/acpcreation/NexusProducts/IQServer/nexus-iq-cli-1.156.0-01.jar'
temp_download_dir = '/Users/acpcreation/NexusProducts/IQ-Scripts/nxrm-scan/' #Include trailing '/'
createMasterReport = True #Add a final scan containing all the artifacts in the scan directory

# End of user input

page_number = 0
def initial_comp_list(page_number):
    page_number = page_number + 1
    print(page_number)
    if page_number == 1:
        theurl = nxrm_url + "/service/rest/v1/components?repository=" + str(repo_name)
        print(theurl)
    else:
        theurl_continuation = nxrm_url + "/service/rest/v1/components?continuationToken=" + str(cont_token) + "&repository=" + str(repo_name)
    # fetch report from uri
    res = requests.get(theurl, auth=(nxrm3_username, nxrm3_password))

    # Load result string to json
    json_data = json.loads(res.text)
    # pprint(json_data)

    cont_token = (json_data['continuationToken'])
    print(cont_token)

    for items in json_data['items']:
        item_text = (items['assets'][0]['downloadUrl'])
        #pprint.pprint(item_text)
        glob_type = item_text[-3:]
        #print(glob_type)
        if glob_type not in ["pom"]:
            #print(glob_type)
            comp_url = (items['assets'][0]['downloadUrl'])
            print("The following will be downloaded and scanned by IQ server")
            print(comp_url)
            dlfile = urlparse(comp_url)
            dlfilename = os.path.basename(dlfile.path)
            print(dlfilename)
            print("")

            #Download file command 
            download_cmd = "cd " + temp_download_dir + " &&  curl  -u "+nxrm3_username+":"+str(nxrm3_password)+" -X GET " + str(comp_url) + " -O -J"
            subprocess.call([download_cmd], shell=True)
            
            #Trigger IQ scan
            print('The IQ scanning CLI command to be invoked is')
            iq_cli_cmd = "java -jar " + path_to_cli_jar + " -a \'" + iq_username + ":" + iq_password + "\' -i " + iq_app_name_prefix +"-"+ items['name']+ " -s "+ iq_url + " -t "+iq_phase+" -O "+iq_organization_id +" " + temp_download_dir+items['name']
            print(iq_cli_cmd)
            subprocess.call([iq_cli_cmd], shell=True)
            
            # Get the SBOM
            # iqurl = iq_url + "/api/v2/applications?publicId="+ iq_app_name_prefix +"-"+ items['name']+ 
            # print(iqurl)
            # iqres = requests.get(iqurl, auth=(iq_username, iq_password))

            # Load result string to json
            # json_iq_data = json.loads(iqres.text)
            # pprint(json_iq_data)
            # print("Internal App ID")

            # try:
            #     id = json_iq_data["applications"][0]["id"]
            #     print(id)
            #     sbom_url = iq_url + "/api/v2/cycloneDx/1.4/" + str(id) + "/stages/build" 
            #     print(sbom_url)
            #     payload={}
            #     headers = {
            #         'Accept': 'application/xml',
            #         'Authorization': 'Basic YWRtaW46TmV4dXMhMjM=',
            #         'Cookie': 'CLM-CSRF-TOKEN=b302408b-aa15-4c76-8653-11b44fd76f17'
            #     }
            #     sbom_response = requests.request("GET", sbom_url, headers=headers, data=payload)
            #     # print(sbom_response.text)
            #     sbom_filename = "sbom" + dlfilename + ".json"
            #     print(sbom_filename)
            #     with open(sbom_filename,"w") as outfile:
            #         json.dump( sbom_response.text, outfile)
            # except:
            #     pass
    
    if createMasterReport == True:
        print('Creating Master Report of all artifacts...')
        iq_cli_cmd = "java -jar " + path_to_cli_jar + " -a \'" + iq_username + ":" + iq_password + "\' -i " + iq_app_name_prefix +" -s "+ iq_url + " -t "+iq_phase+" -O "+iq_organization_id+" " + temp_download_dir
        print(iq_cli_cmd)
        subprocess.call([iq_cli_cmd], shell=True)

    return cont_token

def continued_comp_list(cont_token, page_number):
    print(cont_token)
    page_number = page_number + 1
    print("The page number is " + str(page_number))


if __name__ == "__main__":
    cont_token = initial_comp_list(page_number)
    continued_comp_list(cont_token,page_number)


#Based off of Paul Meharg's script: https://github.com/sonatype/se-scripts/blob/e635a3cca7c9ca80ade6029f87cb7c9c00c1d065/paul/NXRM-download-scan-hosted-sbom.py
