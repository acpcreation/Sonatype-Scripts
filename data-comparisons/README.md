
# Data Comparison Assistant
*Welcome!*
Comparing data between Sonatype and competitors can be tedius, difficult, and often confusing.

This script will help you compare the reports between Sonatype and the competitor.

```
Contributors:
    - Alexander Plattel - aplattel@sonatype.com
    - Irina Tishelman - itishelman@sonatype.com
    - Andrew Haigh - ahaigh@sonatype.com
    - Austin Steffes - asteffes@sonatype.com
```

## Intro
All you really need to get some good statistics in comparing Sonatype's data against a competitor with this script is `*a list of components and associated CVEs*`. Then we can hook into Nexus IQ Server to pull Sonatype's data.

Below you will find the details of how all this works.

```
Note: 
Past comparisons with scan results and `.md files` detailaing important findings can be found in the `comparison-reports` folder for reference.
```



## Requirements
```
- Python installed
- Prospect has scanned the *same* application (and version) with a competitor SCA tool and with IQ and the data is exportable from the other tool.
```

## Comparison Setup
In order to best execute this data comparison script we will need a few resources... FOLLOW THESE STEPS CAREFULLY!

1. You will need to get the competitor data in 1 of 2 ways:
    a. (Preferred) As a `.csv` report including the column headers: "Component", "CVEs", and "License" (if desired/applicable - optional). The script will use this name to identify the columns for the fields.
    
    b. As a Either as a CycloneDX SBOM `.json` report including the following fields:
        
        [{
            
            "purl" : "pkg:ecosystem/example-name@0.0.0", - OR - "name" : "example-name", "version" : "0.0.0"
            "cve" : ["CVE-123"], //FIX
            "licenses" : [{"license":{"id":"License-ID"}}] - OR - "licenses" : [{"license":{"name":"License-Name"}}]
        
        },...]

    
    Upload either of these files to the `input\<competitor>\` folder.

## Pre-check START
Put the competitor source files into the input directory
Each competitor source file is different
Pre-work will determine how close the input file matches the application source. Provides additional validation of a data comparison to Sonatype if it can be shown that the input file does not even compare favourably with the application source.

Modify 'prework_settings.py' and configure your variables. Some entries are there already
```
    appShort = "WebGoat"
    #appShort = "NodeGoat"
    #appShort = "struts2rce"
```
You can run mvn dependedncy:analyze and mvn dependency:tree to be used by parseMvnDepend.py to create a mvn-depend-processed<app>.txt (a mvn SBOM)
```
$ mvn dependency:tree > 'input/prework/mvn-depend-tree-<prework_settings.appShort>'
$ mvn dependency:analyze > 'input/prework/mvn-depend-analyse-<prework_settings.appShort>'
```
Clean the raw tree file to remove above and below the tree

Run parseMvnDepend.py to take the raw files and produce combined and 'clean' file for next step -- 'processedFiles/prework/mvn-depend-processed-<prework_settings.appShort>'

Or

Run npm list -depth=10. Then run parseNpmListDepth_10.py to create an npm SBOM.

# Note
Need to have run at least 'getAPIRemediationData' and 'deeperDataStats' for this project to create a comparison SBOM report.json

Run mvn<competitor>.py to compare the competitor to the mvn SBOM, - writes to output/prework/mvn-comparison-<app>-<competitor>.json

Or
Run npm<competitor>.py to compare the competitor to the npm SBOM, - writes to output/prework/npm-comparison-<app>-<competitor>.json

## Pre-check END

1. You will need to get access to the Sonatype IQ scan results in 1 of 2 ways:
    a. If this is an on-prem POC (where IQ is installed on the prospect's machine), get a CycloneDX SBOM export from them, and then scan that into your own instance of Lifecycle. 
    b. If this is a hosted POC (where IQ is hosted by Sonatype for the prospect and directly accessible), ensure you have credentials to access the reports

2. Configure required variables in 'settings.py' file to reflect the environment
        baseURL = "http://localhost:8070/"
        username = <IQ username>
        password = <IQ password>
        applicationID = "<Lifecycle application name>"
        appShort = "WebGoat"
        stage = "<Lifecycle stage>" - [source | build | stage-release | release ] (build is the default)
        compShort = "<competitor>" - [OWASP | jfrog | mend | snyk | google | HCL ]

3. Configure Optional variables in the settings.py environment. Set to True if you want to run these options. First time through you need to run all 3 functions for isApiRemediationData, isDeeperDataStats, and isMergeLicenses (ie: set to True)
        `compareLicenses` - Only set to true if license data is included in the competitor SBOM.
        `isApiRemediationData` - gets the project from IQ including all of the remediation data
        `isDeeperDataStats` - counts up several useful stats including Sonatype Advisory Notices, etc.
        `isMergeLicenses`

```
Note:
The reason we are connecting to IQ Server directly is because we are going to gather some deeper data analytics which we can only get directly from Nexus Lifecycle.
```

That's it!
If you followed the steps correctly you should be able to move on to the next section.


## Steps to Run
Once the variables above have been set we can simply run the `main.py` file to run the project.

```
> python main.py

Or for Python3:
> python3 main.py 
```

This will initiate the project and run the `getAPIRemediationData.py`, `deeperDataStats.py`, and `compareData.py` files.

- `getAPIRemediationData.py` gets the project from IQ including all of the remediation data. This can take several minutes to run.
    - writes to processedFiles/sonatype-<sbom/licenses>-<appShort>.json

- `deeperDataStats.py` counts up several useful stats including Sonatype Advisory Notices, etc.
    - writes to output/enhancedData-<appShort>.json

-  Various 'parse<compShort>.py' to normailze the competitor source files.
    - writes to processedFiles/dependency-check-report-processed-<appShort>-<compShort>.csv

- `compareData.py` extracts the information from Sonatype and the competitor source files, and compares the findings.
    - writes to output/csv-data-comparison-<appShort>-<compShort>.csv and output/data-comparison-<appShort>-<compShort>.json


The `getAPIRemediationData()` function (and file) takes quite some time to run and so you really only need to run it once per project and then make sure you don't delete the `sonatype-bom.json` file from the `processedFiles` folder. The other functions will be able to read this file in future runs if you want to play with the data. ```In the `settings.py` file you can turn 'isApiRemediationData' to False if you want to skip this step.```

The rest of the results are written to the `output` folder in the project.


## Looking at the Results
The findings are currently written to `.json` files which are readable to the human eye if you take your time to read the fields names and values.


### The enhanced-data.json and deeperDataStats() Function
The `deeperDataStats()` function (and file) gathers some of the enhanced Sonatype data which could prove valuable in a data comparison writeup. Here is a breakdown of the ouput file (`enhanced-data.json`): 

- `Advisories`: list of the unique CVEs which contain Sonatype Advisory Notices and the notice itself.
- `TotalAdvisories`: count of all the Advisories that were found.
- `UniqueAdvisories`: count of all the unique Advisories that were found.
- `Workarounds`: list of all the vulnerability data which contains a workaround. This is helpful because not all vulnerabilities can be fixed by a version change. The workarounds show the deep research we do on issue remediation.
- `TotalWorkarounds`: count of all the Workarounds found.


### The data-comparison.json and compareData() Function
The `compareData()` function (and file) do a number of powerful comparisons to generate value. It looks at component names, CVEs, licenses, and counts for all of these. The `data-comparison.json` file is the output result of running this file. Here is a breakdown of the output file (`data-comparison.json`):

- `componentsFoundByBoth` count of components found by both tools. If this number is higher than either of the other tool's unique findings, then that simply means component duplicates were found.

- `uniqueComponentsFoundBySonatype` count of unique components found by Sonatype.
- `uniqueComponentsFoundByCompetitor` count of unique components found by competitor.

- `componentMissedByCompetitor` list of components competitor did not find during scan, that were found by Sonatype.
- `componentMissedByCompetitorLength` length of list of components competitor did not find during scan.

- `additionalCompetitorComponents` list of components Sonatype did not find during scan, that were found by competitor.
- `additionalCompetitorComponentsLength` length of list of components Sonatype did not find during scan.

- `potentialMatches` this field does some fuzzy matching (by slicing the component name into pieces) to see if the competitor found a similar or incorrectly versioned component which didnt appear in the exact match above. The `level` number is the level on confidence we have in the potential match, and 9 will be the highest confidence. Also we include the path data here to show you where we found the component.
- `potentialMatchesLength` length of the list of petnetial matches

- `cveFoundByBoth` count of same CVEs found by both scanning tools.
- `cveMissingCompetitor` list of CVEs that competitor did not find during scan, that were found by Sonatype. If this is a Sonatype CVE then we will also list any custom competitor CVEs which might match up.
- `cveMissingCompetitorLength` length of `cveMissingCompetitor`.

- `additionalCompetitorCVEs` list of CVEs that Sonatype did not find during scan, that were found by competitor (including the number of times the CVE was repeated in case of false positives).
- `additionalCompetitorCVEsLength` length of `additionalCompetitorCVEs`.

- `sonatypeFoundLaterUpdatedCVEs` is a list of Sonatype custom CVEs which have correlating plubic CVEs (Yes we do also look at these secondary public CVEs when comparing - Thanks Irina!).

- `10WorstCompontnentsMissedByCompetitor` 10 worst CVEs that the competitor did not find. These represent the worst risk omitted by the competitor scan and risk to the organization. `score` is the total score of the summed up CVE severities.

- `badLicenseInComponentsMissedByCompetitor` list of components that the competitor missed which have a level 7 or above license threat or policy violation.
- `badLicenseInComponentsMissedByCompetitorLength` length of the `badLicenseInComponentsMissedByCompetitor`.

(optional - based on checkLicenses flag in settings.py)
- `licensingDiscrepencies` list of components found by both tools which had differing license information.
- `licensingDiscrepenciesCount` count of the list of components found by both tools with license discrepencies.


### The csv-data-comparison.csv File
The `compareData()` function also prints a .csv file containing an easy to read overview of the data comparison showing all the matched components and their associated CVEs. These results can be found in the `csv-data-comparison.csv` file.


### How do I interpret all this?
Results often vary greatly between tools. But do not be alarmed. TRUST THE DATA AND ACTUALLY READ THE REPORT! You might be surprised at how good we are at what we do (we being Sonatype). 

*Did Sonatype have a lot more components than the competitor?* Our binary scan will often pick up packages missed by other tools (especially if they rely on manifest scanning or don't find all the transitive dependencies). This is why we include the path data for every component we found, so we can PROVE what we found and where.

*Did the competitor have a lot more components than Sonatype?* Inferrior scanning techniques such as name based matching, fuzzy component matching, or component prediction (assuming that because component A is present component B must be also) will often lead to a lot of noise of things being found which are not actually there.

Think through these and other question and remember, 99% of the time, our data is better.

Our scanning process will consistently identify the right components. If you start diving into the details of the `data-comparison.json` and it really doesnt make sense. Ask yourself:
- Did we REALLY scan the same thing?
- Should I have used any plugins or data prep steps (for Gradle, Python, or others)?
- Did the scan occur within source control rather than with our CLI?
- Other considerations.


### Thats it! Good luck, and happy selling!

## 
Copyright - Sonatype 2023
