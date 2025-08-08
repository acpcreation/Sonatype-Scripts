#!/bin/bash

# Define the function to read the payload
read_payload() {
    echo "Reading webhookPayload.json"
    cat webhookPayload.json
}

# Define the function to write to the file
write_to_file() {
    echo "Writing to uniqueIssues.json"
    echo "$1" > uniqueIssues.json
}

# Main script
echo "Starting parse unique issues..."
payload=$(read_payload)
echo "Found $(jq '.policyAlerts | length' <<< "$payload") total issues"

declare -A uniqueItems

for row in $(jq -r '.policyAlerts[] | @base64' <<< "$payload"); do
    _jq() {
        echo ${row} | base64 --decode | jq -r ${1}
    }

    component=$(_jq '.componentFacts[].displayName')
    highestViolation=$(_jq '.policyName')
    violationSeverity=$(_jq '.threatLevel')
    reasons=$(jq -r '.componentFacts[].constraintFacts[].satisfiedConditions[].reason' <<< "$(_jq '.')")
    project=$(jq -r '.application.publicId' <<< "$(_jq '.')")

    issue=$(jq -n \
                --arg component "$component" \
                --arg highestViolation "$highestViolation" \
                --arg violationSeverity "$violationSeverity" \
                --arg reasons "$reasons" \
                --arg project "$project" \
                '{component: $component, highestViolation: $highestViolation, violationSeverity: $violationSeverity, reasons: $reasons, project: $project}')

    if [[ -z "${uniqueItems["$component"]}" ]]; then
        uniqueItems["$component"]=$issue
    else
        existingIssue=${uniqueItems["$component"]}
        existingReasons=$(jq -r '.reasons' <<< "$existingIssue")
        for reason in $reasons; do
            if [[ $existingReasons != *"$reason"* ]]; then
                existingReasons+=$'\n'"$reason"
            fi
        done
        uniqueItems["$component"]=$(jq --arg reasons "$existingReasons" '.reasons = $reasons' <<< "$existingIssue")
    fi
done

# Format output
output="["
for key in "${!uniqueItems[@]}"; do
    output+="${uniqueItems[$key]},"
done
output=${output::-1}"]"

write_to_file "$output"
echo ""
echo "$output"
echo ""
echo "Done! ${#uniqueItems[@]} unique issues found."