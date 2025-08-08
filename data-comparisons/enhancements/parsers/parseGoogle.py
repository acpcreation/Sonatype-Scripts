import csv
import requests
import settings
import time

from bs4 import BeautifulSoup

competitorData = []
extraData = []

def import_reports():
    global competitorData

    print("Reading " + googleOSV + "... ")
    f = open(googleOSV, "r")

    cols = {
        "identifier":None,
        "lic":None,
    }
    indexSet = False

    csvData = csv.reader(f)

    for lines in csvData:
        if not indexSet:
            cols = get_license_column_indicies(cols, lines)
            indexSet = True
            continue
    
        URL = lines [cols["cve"]]
        URL = URL.replace(" ","")
    
    #URL = "https://github.com/advisories/GHSA-fwr7-v2mv-hh25/"
    #URL = "https://osv.dev/vulnerability/GHSA-fwr7-v2mv-hh25"
    
        page = requests.get(URL)
    
        soup = BeautifulSoup(page.content, "html.parser")
        
        pos = soup.text.find("CVE")
        if pos > 0:
            subStr = soup.text[pos:]
            subStr = subStr[0:subStr.find("\n")]
            subStr = subStr[0:subStr.find(" ")]
            
            component = lines[cols["identifier"]]
            dataObj = {"component":component, "licenses":[], "cve":[subStr]}
            if not dataObj in competitorData:
                competitorData.append(dataObj)
                print("[X] Component:" + component + ", URL:" + URL + " : " + subStr)
            else:
                 print("[D] Component:" + component + ", URL:" + URL + " : " + subStr)

        else:
            dataObj = {"component":component, "licenses":[], "cve":[]}
            if not dataObj in competitorData:
                extraData.append(dataObj)
            subStr = "..."
            print("[-] Component:" + component + ", URL:" + URL + " : " + subStr)

        time.sleep(3)

    for e in extraData:
        eComp = e["component"]
        found = False

        for c in competitorData:
            cComp = c["component"]
            if eComp == cComp:
                found = True
                break

        if not found:
             competitorData.appaend(e)   
        
    print("End of file")


def get_license_column_indicies(cols, lines):
    print("\tFound column headers: ")
    for i in range(len(lines)):
        item = lines[i].lower()
#        print("\t\t- <"+item+">")
        if item == "components":
            cols["identifier"] = i
        if item == "cves":
            cols["cve"] = i

    return cols


def format_csv_report():
    # Write to CSV file
    csvReport = []
    header = []

    header = [
        "component",
        "licenses",
        "cve"]

    for i in competitorData:
        if len(header) > 0:
            component = str(i["component"])

            csvReport.append([
                i["component"],
                "; ".join(str(x) for x in i["licenses"]),
                "; ".join(str(y) for y in i["cve"])
            ])
        else:
            print("Define header")


    #Sort by match confidence and then name    
#    csvReport.sort(key=lambda row: (-1*int(row[2] or 0), row[3], row[0]), reverse=False)
    csvReport[:0] = [header]

    with open(outputFile,"w+") as my_csv:
        csvWriter = csv.writer(my_csv,delimiter=',')
        csvWriter.writerows(csvReport)

    print("CSV report written to '" + outputFile + "'...")


#==========================
#========== MAIN ==========
#==========================

def main():
    print("\n- INITIATING JFROG PARSING - ")
    global googleOSV, outputFile
    googleOSV = "input/" + settings.compShort + "/" + settings.compShort + "-" + settings.appShort + "osv.csv"
    outputFile = "processedFiles/" + settings.compShort + "/dependency-check-report-processed-" + settings.appShort + "-" + settings.compShort + ".csv"

    import_reports()

    print("\nResults written to '" + outputFile + "'...")
    
    format_csv_report() #Print report in CSV format


if __name__ == "__main__":
    main()
