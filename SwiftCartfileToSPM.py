#!/usr/bin/env python
import json
pins = []

# 
# This script converts a Carthage manifest file to Swift Package Manager format.
# This conversion allows you to take advantage of Nexus Lifecyce's dependency
# scanning and security evaluation by providing a supported filetype for 
# evaluation. Due to the overlap of libraries between Carthage and the Swift
# Package Manager we are safely able to do this conversion, giving your team 
# insight into which open source libraries are being used.
#
# Both Cartfile and Cartfile.resolvedfiletypes are supported.
#
# Steps:
#   1. Update the read file location
#   2. Update the desired file publish destination
#   3. Run this Python script
#   4. Run an evaluation of this directory with the Nexus Lifecycle CLI
#

fileLocation = "path/to/Cartfile.resolved" #UPDATE read file location
publishDestination = "path/to/Package.resolved" #UPDATE publish destination


def readCartfiles():
    f = open(fileLocation, "r") 
    lines = f.read()
    f.close()
    lines = lines.split("\n")
    for i in range(len(lines)-1):
        subData = lines[i].split("\"")
        pubProj = subData[1].split("/") #subData = publisher/package
        version = subData[3].replace("v","")

        obj = {
            "package": pubProj[0].strip(), #package
            "publisher": subData[1].strip(), #publisher/package
            "version": version.strip() #1.0.0
        }
        createPins(obj)



#Assign pins for Swift Package Manager format
def createPins(e):
    pin  = {
        "package": e["package"],
        "repositoryURL": "https://github.com/"+e["publisher"]+".git",
        "state": {
            "branch": None,
            "revision": "",
            "version": e["version"]
        }
    }
    pins.append(pin)



#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":
 
    print("Running..")
    readCartfiles()
    f = open(publishDestination, "w") #Output: Package.resolved
    writeData = {
        "object": {
            "pins": pins
        },
        "version": 1
    }

    f.write(json.dumps(writeData))
    f.close()
    print("Carthage written to "+publishDestination+" with "+str(len(pins))+" components!")
