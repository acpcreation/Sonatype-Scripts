#!/usr/bin/env python
import json
import csv
import math
import prework_settings

# ========= ENVIRONMENT VARIABLES ========
npmListFile = "../input/prework/npm-list-" + prework_settings.appShort + ".txt"
outputFile = "../processedFiles/prework/npm-list-processed-" + prework_settings.appShort + ".txt"
# =============================================

npmListData = []
npmProcessedData = []

#Read both SBOMs
def import_files():
    global npmListData, npmProcessedData
    npmListData = read_npm_list()
    npmProcessedData = npmListData # process_components(mvnTreeData, mvnAnalyzeData)
    print("Processed " + str(len(npmProcessedData)) + " npm items")


#Parse competitor data file
def read_npm_list():
    print("Reading "+npmListFile+"... ")
    f = open(npmListFile, "r")

    preNpmListData = []
    uniqueNpmListData = []

    skipFirstLine = True

    rawTreeData = csv.reader(f)

    for rawLine in rawTreeData:
        if skipFirstLine:
            skipFirstLine = False
            firstLine = rawLine[0]

        else:
            line = rawLine[0]
            line = line.replace("├", "")
            line = line.replace("─", "")
            line = line.replace("┬", "")
            line = line.replace("└", "")
            line = line.replace(" ", "")
            line = line.replace("│", "")
            line = line.replace("deduped", "")
            parts = line.split("/")
            if len(parts) == 1:
                line = line.replace("@", ":")
            else:
                line = parts[0] + "/" + parts[1].replace("@", ":")
            preNpmListData.append(line)

    f.close()

    preNpmListData.sort()
    
    for n in range(len(preNpmListData)):
        npmStr = preNpmListData[n]

        found = False
        for u in range(len(uniqueNpmListData)):
            unpmStr = uniqueNpmListData[u]

            if npmStr == unpmStr:
                found = True

        if found == False:
            uniqueNpmListData.append(preNpmListData[n])

#    uniqueNpmListData.insert(0, firstLine)
    return uniqueNpmListData


def format_csv_report():
    # Write to CSV file
    npmReport = []

    for i in npmProcessedData:
         npmReport.append([i])

    with open(outputFile,"w+") as my_csv:
        csvWriter = csv.writer(my_csv,delimiter=',')
        csvWriter.writerows(npmReport)

    print("CSV report written to '" + outputFile + "'...")


#==========================
#========== MAIN ==========
#==========================

def main(e):
    print("\n- INITIATING NPM PARSING - ")
    global npmListFile
    npmListFile = e["npmListFile"]

    import_files()

    print("\nResults written to '" + outputFile + "'...")
    
    format_csv_report() #Print report in CSV format

    
if __name__ == "__main__":
    main({
        "npmListFile":npmListFile
    })