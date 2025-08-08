#!/usr/bin/env python

import json
import requests
import subprocess
import os
from urllib.parse import urlparse


# REQUIREMENTS:
#   1. Update all the environment variables below 
#   2. Turn on automatic applications in IQ
#   3. In IQ create an Organization, and copy the organization ID into the iq_organization_id field. 
#       - Ex: https://help.sonatype.com/iqserver/integrations/nexus-iq-cli#NexusIQCLI-organizationLocatingtheorganizationID


# Environment Variables
iq_app_name_prefix = "Maven-Hosted-NXRM" #Prefix for each app scan
iq_organization_id = "f9b233f57e994671969baf913f2bf218" #https://help.sonatype.com/iqserver/integrations/nexus-iq-cli#NexusIQCLI-organizationLocatingtheorganizationID

nxrm_url = "http://localhost:8081/" #INCLUDE trailing '/'
nxrm3_username = "admin"
nxrm3_password = "admin!23"
repo_name = "maven-releases"

iq_url = "http://localhost:8070/" #INCLUDE trailing '/'
iq_username = "admin"
iq_password = "admin!23"
iq_phase = "release"
path_to_cli_jar = 'nexus-iq-cli-1.156.0-01.jar'
temp_download_dir = 'nxrm-scan/' #INCLUDE trailing '/'

scanEachIndividualArtifact = True #Scan each individual artifact downloaded
createMasterReport = True #Create a final scan containing ALL the artifacts in the scan directory
# End of user input

page_number = 0
def initial_comp_list(page_number):
    page_number = page_number + 1
    print(page_number)
    if page_number == 1:
        theurl = nxrm_url + "service/rest/v1/components?repository=" + str(repo_name)
        print(theurl)
    else:
        theurl_continuation = nxrm_url + "service/rest/v1/components?continuationToken=" + str(cont_token) + "&repository=" + str(repo_name)
    # fetch report from uri
    res = requests.get(theurl, auth=(nxrm3_username, nxrm3_password))

    # Load result string to json
    json_data = json.loads(res.text)
    # print(json_data)

    cont_token = (json_data['continuationToken'])
    print(cont_token)

    for items in json_data['items']:
        item_text = (items['assets'][0]['downloadUrl'])
        #print(item_text)
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
            
            if scanEachIndividualArtifact == True:
                #Trigger IQ scan
                print('The IQ scanning CLI command to be invoked is:')
                iq_cli_cmd = "java -jar " + path_to_cli_jar + " -a \'" + iq_username + ":" + iq_password + "\' -i " + iq_app_name_prefix +"-"+ dlfilename+ " -s "+ iq_url + " -t "+iq_phase+" -O "+iq_organization_id +" " + temp_download_dir+dlfilename
                print("\t"+iq_cli_cmd)
                print()
                subprocess.call([iq_cli_cmd], shell=True)
            
    
    if createMasterReport == True:
        print('Creating Master Report of all artifacts...')
        iq_cli_cmd = "java -jar " + path_to_cli_jar + " -a \'" + iq_username + ":" + iq_password + "\' -i " + iq_app_name_prefix +" -s "+ iq_url + " -t "+iq_phase+" -O "+iq_organization_id+" " + temp_download_dir
        print("\t"+iq_cli_cmd)
        print()
        subprocess.call([iq_cli_cmd], shell=True)
        
    return cont_token

def continued_comp_list(cont_token, page_number):
    print(cont_token)
    page_number = page_number + 1
    print("The page number is " + str(page_number))


if __name__ == "__main__":
    cont_token = initial_comp_list(page_number)
    # continued_comp_list(cont_token,page_number)


#Based off of Paul Meharg's script: https://github.com/sonatype/se-scripts/blob/e635a3cca7c9ca80ade6029f87cb7c9c00c1d065/paul/NXRM-download-scan-hosted-sbom.py
