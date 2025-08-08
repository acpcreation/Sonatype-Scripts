#!/usr/bin/env python
import json
from xml.dom import xmlbuilder
import requests
import os

xmlsbom = ""

#Get all the file names
def collect_all_file_names():
    print("Collecting all file names...")
    
    path = '/Users/acpcreation/NexusProducts/IQ-Scripts/Yocta/tsmeta_src'
    global list_of_files
    list_of_files = []

    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(file)
            # list_of_files.append(os.path.join(root,file)) #Full path

    # print(list_of_files)
    print(str(len(list_of_files))+" Files ...")


#Read JSON files
def read_files_convert_to_sbom():
    global xmlsbom 
    xmlsbom += "<components>"
    for name in list_of_files:
        f = open("tsmeta_src/"+name) 
        lines = f.readlines()

        if(len(lines)>0):
            content = ""
            for line in lines:
                content += line

            # print(content)
            json_data = json.loads(content)
            # print(json_data)
            xmlsbom += xml_component(json_data)

    xmlsbom += "</components>"


# Generate component details
def xml_component(e):
    print(e["cve_product"]+" - "+e["cve_version"])

    #Eliminate multiple licenses
    xmlLicenses = ""
    e["license"] = e["license"].replace('|', '&')
    licenses = e["license"].split('&')
    # for lic in licenses:
    #     xmlLicenses += '''\n<license>
    #       <id>{}</id>
    #     </license>'''.format(lic.strip())

    finalLicense = licenses[0].split('-')
    if len(finalLicense)>1 :
        finalLicense = finalLicense[0]+"-"+finalLicense[1]
    else:
        finalLicense = finalLicense[0]

    #For some reason these licenses cause errors
    if finalLicense == 'PD' or finalLicense == 'BSD-3':
        finalLicense = ""
    
    # print(e["cve_product"]+" \t"+ finalLicense)

    xmlLicenses = ''
    if len(finalLicense)>0:
        xmlLicenses = '''<license>
            <id>{}</id>
        </license>'''.format(finalLicense.strip())

    #Final component data
    component = """\n<component type="library">
      <name>{}</name>
      <version>{}</version>
      <licenses>
        {}
      </licenses>
      <purl>{}</purl>
      </component>""".format(e["cve_product"], e["cve_version"], xmlLicenses, e["homepage"])
    return component



#Read JSON files
# def read_files_convert_to_sbom():
#     global xmlsbom 
#     xmlsbom += "<components>"

#     xmlsbom += "</components>"



#Print to actual file
def write_to_file(e):
    e +='</bom>'

    f = open("bom.xml", "w")
    f.write(e)
    f.close()
    print("Printing to..... bom.xml")


#MAIN
if __name__ == "__main__":
    print("Running.. This will take a few minutes..")

    xmlsbom = """<?xml version="1.0" encoding="UTF-8"?> 
        <bom xmlns="http://cyclonedx.org/schema/bom/1.4" serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1">
        <metadata>
            <component type="application" bom-ref="acme-app">
                <name>Yocta Application</name>
                <version>1.0.0</version>
            </component>
        </metadata>"""

    collect_all_file_names()
    read_files_convert_to_sbom()
    write_to_file(xmlsbom)

