#!/usr/bin/env python
import json
import csv
import math
import prework_settings

# ========= ENVIRONMENT VARIABLES ========
mvnTreeFile = "../input/prework/mvn-depend-tree-" + prework_settings.appShort + "-raw.txt"
mvnAnalyzeFile = "../input/prework/mvn-depend-analyze-" + prework_settings.appShort + "-raw.txt"
outputFile = "../processedFiles/prework/mvn-depend-processed-" + prework_settings.appShort + ".txt"
# =============================================

mvnTreeData = []
mvnAnalyzeData = []
mvnProcessedData = []


#Read both SBOMs
def import_files():
    global mvnTreeData, mvnAnalysisData, mvnProcessedData
    mvnTreeData = read_mvn_tree()
    mvnAnalyzeData = read_mvn_analyze()
    mvnProcessedData = process_components(mvnTreeData, mvnAnalyzeData)
    print("Processed " + str(len(mvnProcessedData) - 3) + " mvn items")


#Parse competitor data file
def read_mvn_tree():
    print("Reading "+mvnTreeFile+"... ")
    f = open(mvnTreeFile, "r")

    mvnTreeData = []

    skipFirstLine = True

    rawTreeData = csv.reader(f)

    for rawLine in rawTreeData:
        line = rawLine[0]
        line = line.replace("[INFO]", "")
        line = line.replace(" ", "")

        if skipFirstLine:
            skipFirstLine = False
            firstLine = line
            firstLine = firstLine.replace(":war", "")

        else:
            line = line.replace("+-", "")
            line = line.replace("|", "")
            line = line.replace("\-", "")
            line = line.replace(":jar", "")
            line = line.replace(":jdk15", "")
            line = line.replace(":compile", "")
            line = line.replace(":provided", "")
            line = line.replace(":test", "")
            mvnTreeData.append(line)

    f.close()

    mvnTreeData.sort()
    mvnTreeData.insert(0, firstLine)
    return mvnTreeData


#Parse competitor data file
def read_mvn_analyze():
    print("Reading "+mvnAnalyzeFile+"... ")
    f = open(mvnAnalyzeFile, "r")

    usedData = []
    unusedData = []
    mvnAnalyzeData = []

    usedFound = False
    unusedFound = False
        
    rawAnalysisData = csv.reader(f)
    for rawLine in rawAnalysisData:
        if len(rawLine) == 0:
            continue

        line = rawLine [0]
        if line.startswith("[WARNING] Used undeclared dependencies found"):
            usedFound = True
            continue
        if line.startswith("[WARNING] Unused declared dependencies found"):
            usedFound = False
            unusedFound = True
            continue
        if line.startswith("[INFO] ------------------------------------------------------------------------"):
            unusedFound = False

        if usedFound or unusedFound:
            line = line.replace("[WARNING]    ", "")
            line = line.replace(":jar", "")
            line = line.replace(":compile", "")
            line = line.replace(":provided", "")
            line = line.replace(":test", "")

        if usedFound:
            usedLine = "U_UD_" + line
            usedData.append(usedLine)
        
        if unusedFound:
            unusedLine = "UU_D_" + line
            unusedData.append(unusedLine)

    f.close()

    usedData.sort()
    usedData.insert(0,"## Used undeclared dependencies")
    unusedData.sort()
    unusedData.insert(0,"## Unused declared dependencies")

    for i in range(len(usedData)):
        mvnAnalyzeData.append(usedData[i])

    for i in range(len(unusedData)):
        mvnAnalyzeData.append(unusedData[i])

    return mvnAnalyzeData


def process_components(mvnTreeData, mvnAnalyzeData):
    print("Process the two data files")
    mvnProcessedData = []
    mvnProcessedData = mvnAnalyzeData
    print("Analyzed " + str(len(mvnAnalyzeData) - 2) + " components")

    mvnProcessedData.append("## Tree Data")
    
    duplicate = 0
    for i in range(len(mvnTreeData)):
        treeComp_U_UD = "U_UD_" + mvnTreeData[i]
        if treeComp_U_UD in mvnProcessedData:
            duplicate += 1
            continue
        treeComp_UU_D = "UU_D_" + mvnTreeData[i]
        if treeComp_UU_D in mvnProcessedData:
            duplicate += 1
            continue
        mvnProcessedData.append(mvnTreeData[i])
    print("Tree has " + str(len(mvnTreeData)) + " components")
    print("Tree has " + str(duplicate) + " U_UD or UU_D components")

    return mvnProcessedData


def format_csv_report():
    # Write to CSV file
    mvnReport = []

    for i in mvnProcessedData:
        mvnReport.append([i])

    with open(outputFile,"w+") as my_csv:
        csvWriter = csv.writer(my_csv,delimiter=',')
        csvWriter.writerows(mvnReport)

    print("CSV report written to '" + outputFile + "'...")


#==========================
#========== MAIN ==========
#==========================

def main(e):
    print("\n- INITIATING MVN PARSING - ")
    global mvnTreeFile, mvnAnalysisFile
    mvnTreeFile = e["mvnTreeFile"]
    mvnAnalyzeFile = e["mvnAnalyzeFile"]

    import_files()

    print("\nResults written to '" + outputFile + "'...")
    
    format_csv_report() #Print report in CSV format

    
if __name__ == "__main__":
    main({
        "mvnTreeFile":mvnTreeFile,
        "mvnAnalyzeFile":mvnAnalyzeFile
    })