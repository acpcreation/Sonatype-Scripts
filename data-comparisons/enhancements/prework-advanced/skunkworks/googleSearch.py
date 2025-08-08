try:

    from googlesearch import search

except ImportError: 

    print("No module named 'google' found")
 
# to search

#query = "helmet-csp Package for Node.js lib/transform-directives-for-browser.ts transformDirectivesForBrowser() Function Default Directive Handling Content Security Policy Bypass"
#query = "The package underscore from 1.13.0-0 and before 1.13.0-2, from 1.3.2 and before 1.12.1 are vulnerable to Arbitrary Code Injection via the template function, particularly when a variable property is passed as an argument as it is not sanitized."
#query = "A vulnerability was found in the minimatch package. This flaw allows a Regular Expression Denial of Service (ReDoS) when calling the braceExpand function with specific arguments, resulting in a Denial of Service."
#query = "Minimist <=1.2.5 is vulnerable to Prototype Pollution via file index.js, function setKey() (lines 69-95)."
#query = "minimist Package for Node.js --__proto__.y=Polluted Argument Handling Prototype Pollution Remote Property Manipulation"
query = "The debug module is vulnerable to regular expression denial of service when untrusted user input is passed into the o formatter"
#query = "Hawk is an HTTP authentication scheme providing mechanisms for making authenticated HTTP requests with partial cryptographic verification of the request and response"
#query = "yargs-parser could be tricked into adding or modifying properties of Object.prototype using a \"__proto__\" payload"
query = "qs before 6.10.3, as used in Express before 4.17.3 and other products, allows attackers to cause a Node process hang for an Express application because an __ proto__ key can be used."
query = "XStream before version 1.4.14 is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker to run arbitrary shell commands only by manipulating the processed input stream."
query = "Thymeleaf sec: Attribute Username Handling XSS"

for j in search(query, tld="co.in", num=10, stop=10, pause=5):
    if "CVE-" in j or "cve-" in  j:
        print("Found: " + j)
    else:
        print("!found: " + j)