# GitHub Dependabot SCA

- They can only do manifest scanning
- Dependabot does not export data, so we had to copy it into an excel sheet and format it manually.
- There are no further options of reporting on the data besides a list of components in the GitHub project.
- If there are version variables in the manifest file then the component CVEs cannot be identified. Our binary matching allows us to find things in the build artifacts.
- If the open source project is not maintained in GitHub.com then there is no context beyond the name of the component (no information like licensing, other identifiers, etc.).