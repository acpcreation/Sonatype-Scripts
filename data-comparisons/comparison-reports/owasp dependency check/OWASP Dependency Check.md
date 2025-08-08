# OWASP Dependency Check SCA

- They missed 4/5 of the components actually present in the Webgoat application. They found 30 components while we found 160 components.
- They do binary analysis but it detects numerous duplicates of components because of partial binary matching. For example, multiple instances of jQuery were found because of a single hash.
- First time you run the scan it needs to install the entire CVE database which can take quite some time. This takes about 5 minutes. It also checks for and downloads updates to the database every time you trigger the scan.
- The scan uses CVE results from the Sonatype OSS Index (as indicated by a note at the bottom of the report).
- The OWASP scanner outputs a `.html` file with the scan results. No central dashboard for reporting. No ordering of CVEs by severity, first level 9 CVE is after a number of lower level ones.
- No build breaking or security enforcement.
- No remediation data, just CVE descriptions from the NVD/OSS Index.
- Current customer left this tool because it is difficult to set up for scanning different ecosystems like Gradle.