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
iq_app_name = "Docker-Hosted-NXRM"
iq_organization_id = "98acec7545f74c408e7086c7ab6d0fb4" #https://help.sonatype.com/iqserver/integrations/nexus-iq-cli#NexusIQCLI-organizationLocatingtheorganizationID

nxrm_url = "http://localhost:8081/" #Include trailing '/'
nxrm3_username = "admin"
nxrm3_password = "admin!23"
repo_name = "docker-hosted"
nxrm_subdomain_url = "https://docker-a.repo.aplattel.ngrok.io/"

iq_url = "http://localhost:8070/" #Include trailing '/'
iq_username = "admin"
iq_password = "admin!23"
path_to_cli_jar = 'nexus-iq-cli-*.jar'
cache_file_name = "container-scan-cache.json"
##### END OF USER INPUT #####

page_number = 0
cont_token = None
scan_cache = []
scan_count = 0
def initial_comp_list():
    global nxrm_subdomain_url, cont_token, page_number, scan_count

    page_number = page_number + 1
    print("Page " + str(page_number))
    # print(page_number)

    if cont_token == None:
        theurl = nxrm_url + "service/rest/v1/components?repository=" + str(repo_name)
        # print(theurl)
    else:
        theurl = nxrm_url + "service/rest/v1/components?continuationToken=" + str(cont_token) + "&repository=" + str(repo_name)
    
    # fetch report from uri
    res = requests.get(theurl, auth=(nxrm3_username, nxrm3_password))

    # Load result string to json
    json_data = json.loads(res.text)
    # pprint(json_data)

    cont_token = (json_data['continuationToken'])
    print("Continuation Token: "+str(cont_token))

    for items in json_data['items']:
        # pprint(items)
        # print("\nThe following will be remotely scanned by IQ server:")
        nxrm_image_to_scan = nxrm_subdomain_url+str(items['name'])+":"+items['version']
        # print("\t"+nxrm_image_to_scan)
        
        if nxrm_image_to_scan not in scan_cache[repo_name]:
            #Trigger IQ scan
            print('\nThe IQ scanning CLI command to be invoked is:')
            iq_cli_cmd = "java -jar "+path_to_cli_jar+" -a \'"+iq_username+":"+iq_password+"\' -i "+iq_app_name+"-"+items['name']+" -s "+ iq_url + " -t source -O "+iq_organization_id +" container:" +nxrm_image_to_scan
            print("\t"+iq_cli_cmd)
            # print("Scanning...")
            subprocess.call([iq_cli_cmd], shell=True)
            scan_count += 1
            update_cache(nxrm_image_to_scan)
        else:
            print("Skipping cached image: "+nxrm_image_to_scan)


    if cont_token is not None:
        initial_comp_list()
    else:
        print("Done! Evaluated "+str(scan_count)+" images!")


def update_cache(scanned_image):
    print("Updating cache...")
    global repo_name
    with open(cache_file_name, 'r') as f:
        cache_data = json.load(f)
    
    cache_data[repo_name].append(scanned_image)

    with open(cache_file_name, 'w') as f:
        json.dump(cache_data, f, indent=4)


def read_cache():
    global scan_cache, repo_name
    print("Reading cache...")
    with open(cache_file_name, 'a+') as f:
        f.seek(0)
        try:
            scan_cache = json.load(f)
        except json.JSONDecodeError:
            scan_cache = {
                repo_name:[]
            }

    print("Scan Cache: ")
    pprint(scan_cache)

    with open(cache_file_name, 'w') as f:
        json.dump(scan_cache, f, indent=4)
    


if __name__ == "__main__":
    # set_nxrm_env = "export NEXUS_CONTAINER_IMAGE_REGISTRY_USER="+nxrm3_username+" \nexport NEXUS_CONTAINER_IMAGE_REGISTRY_PASSWORD="+nxrm3_password
    # print("Setting environment variables: \n"+set_nxrm_env)
    # subprocess.call([set_nxrm_env], shell=True)
    read_cache()
    initial_comp_list()