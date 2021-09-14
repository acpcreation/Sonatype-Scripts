import requests
import json
import datetime

#This python script allows users to:
#   1) Get all tags 
#   2) Create a new tag 
#   3) Add tag to component 
#   4) Remove tag from component
#   5) Delete tag entirely
#
# All you need to do to update this file is make sure the URI matches your Nexus Repository Manager Instance
# Simply run python3 configure-tags.py

authToken = '' # UPDATE with your auth token
uri = "http://localhost:8081/" # UPDATE with Nexus Repository Manager URI (include the trailing '/') 

def triggerAction(e):
    print()

    #GET ALL TAGS
    if e == "1":
        url = uri+"service/rest/v1/tags"
        payload={}
        headers = {
            'Authorization': 'Basic '+authToken
        }
        response = requests.request("GET", url, headers=headers, data=payload)
        # print(response.text)
        response = json.loads(response.text)

        print("Tags:")
        for i in range(0,len(response["items"])):
            print("\t",i, response["items"][i]["name"])

    #CREATE A NEW TAG
    if e == "2":
        tag = input("New Tag Name: ")
        print("Attributes can be used to give more context and details around tags.")
        attributes = []
        attr = ""
        while attr != "x" and attr != "X":
            attr = input("Enter attribute text (enter 'x' to submit tag and attributes): ")
            if attr != "x" and attr != "X":
                attributes.append(attr)

            print("Tag Attributes: ")
            print(attributes)
            print()

        currentDateTime = datetime.datetime.utcnow().isoformat() + "Z"        
        # payload = {
        #     "name": tag,
        #     "attributes": {
        #         "attributeList": attributes
        #     },
        #     "firstCreated": currentDateTime,
        #     "lastUpdated": currentDateTime
        # }
        # payload = repr(json.dumps(payload, indent=4))
        # payload = payload.replace("\"", "\\\"")
        # payload = payload.replace("\'", "\"")
        # payload = json.dumps(payload)

        # print(payload) 

        attributes = str(attributes)
        attributes = attributes.replace("\'", "\"")
        payload="{\n  \"name\": \""+tag+"\",\n  \"attributes\": {\n    \"attributeList\": "+attributes+"\n  },\n  \"firstCreated\": \""+currentDateTime+"\",\n  \"lastUpdated\": \""+currentDateTime+"\"\n}"
        # print(payload) 

        url = uri+"service/rest/v1/tags"
        headers = {
            'Authorization': 'Basic '+authToken,
            'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        print(response.text)


    #ADD TAG TO COMPONENT
    if e == "3":
        tag = input("Tag: ")
        component = input("Component Name: ")

        url = uri+"service/rest/v1/tags/associate/"+tag+"?wait=true&q="+component
        payload={}
        headers = {
            'Authorization': 'Basic '+authToken
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        response = json.loads(response.text)
        print(response["message"])


    #REMOVE TAG FROM COMPONENT
    if e == "4":
        tag = input("Tag to Remove: ")
        component = input("Component Name: ")
        url = uri+"service/rest/v1/tags/associate/"+tag+"?q="+component
        payload={}
        headers = {
        'Authorization': 'Basic '+authToken
        }
        response = requests.request("DELETE", url, headers=headers, data=payload)
        response = json.loads(response.text)
        print(response["message"])


    #DELETE TAG ENTIRELY
    if e == "5" or e == "x" or e == "X":
        tag = input("Tag to Delete: ")
        url = uri+"service/rest/v1/tags/"+tag
        payload={}
        headers = {
        'Authorization': 'Basic '+authToken
        }
        response = requests.request("DELETE", url, headers=headers, data=payload)
        print(response.text)

#MAIN
print("Started script for tagging in Nexus Repository Manager at: "+uri)
inputValue = ""
while inputValue != "6":
    print()
    print("Select function: \n 1) Get all tags \n 2) Create a new tag \n 3) Add tag to component \n 4) Remove tag from component \n 5) Delete tag entirely \n 6) Exit")
    inputValue = input()
    triggerAction(inputValue)


print("Thanks for using tags in the Nexus Repository Manager!")
print(" - Sonatype")