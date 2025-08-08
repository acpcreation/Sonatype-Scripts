# JFrog Artifactory SCA 

- No way to export all components and CVEs for an application. Reports only include all components with no CVEs, or only components with CVEs.
- Have to either create a report or click down into a bunch of teirs into the artifact storage path to get to vulnerability data. Vulnerability data hidden behind 4 clicks of data (unless you create a report which shows a max of 6 items and you need to tediously paginate).
- Couldnt determine any path (or occurences) data for where they found components.
- Fix version recommendation is not easy to see and doesn't provide any context about why to move versions.
- Gave a bunch of license violations from `.jar` files which were proprietary and have no licenses because they arent open source.
- Violations tab doesnt clearly differ from Security or License tabs (numbers for the collumns don't add up to Violations number).