# Copyright (c) 2011-present Sonatype, Inc. All rights reserved.
# "Sonatype" is a trademark of Sonatype, Inc.

import argparse
import csv
import json
import requests

APPLICATIONS_ENDPOINT = '/api/v2/applications'
APPLICATIONS_CATEGORIES_ENDPOINT = '/api/v2/applicationCategories/application/{}/applicable'
LEGAL_ENDPOINT = '/api/v2/licenseLegalMetadata/application/{}'


def __request(server_url, endpoint, username, password):
    response = requests.get(server_url + endpoint, auth=(username, password))
    if response.status_code != 200:
        raise ConnectionError(response.reason)
    return response.json()


def __filter_application(server_url, username, password, application, categories):
    """ Returns True if the application has a category that exists in the categories list. """
    if not application['applicationTags']:
        return False

    application_tag_ids = []
    for application_tag in application['applicationTags']:
        application_tag_ids.append(application_tag['tagId'])

    response = __request(server_url, APPLICATIONS_CATEGORIES_ENDPOINT.format(application['publicId']), username,
                         password)

    tag_id_to_name = {}
    for applicable_application_category in response:
        tag_id_to_name[applicable_application_category['id']] = applicable_application_category['name']

    for application_tag_id in application_tag_ids:
        if tag_id_to_name[application_tag_id] in categories:
            return True

    return False


def __get_applications(server_url, username, password, categories):
    """ Calls IQ and gets a listing of all public application IDs available to the given user. """
    response = __request(server_url, APPLICATIONS_ENDPOINT, username, password)
    applications = response['applications']
    result = []
    for application in applications:
        if not categories:
            result.append(application['publicId'])
        elif __filter_application(server_url, username, password, application, categories):
            result.append(application['publicId'])

    return result


def __parse_license_data(license_data):
    """ The legal data response includes a 'licenseLegalData' section that maps a license to a threat group, in addition to providing other metadata about that license."""
    result = {}
    if license_data is None:
        return result

    for license in license_data:
        # Exclude multi-licenses here as a multi-license is really composed of individual single licenses.
        if license['isMulti'] == False:
            result[license['licenseId']] = license['threatGroup']['name']

    return result


def __parse_multi_license_data(license_data):
    """ The 'licenseLegalData' section of the response also maps multi-licenses to their individual single licenses, which we need to parse if we want to obtain the license threat group for those single licenses."""
    result = {}
    if license_data is None:
        return result

    for license in license_data:
        if license['isMulti'] == True:
            result[license['licenseId']] = license['singleLicenseIds']

    return result


def __parse_component_data(license_data, multi_license_data, components):
    """Using the provided license and multi-license data, map each component's licenses to their respective threat groups."""
    result = []
    if components is None:
        return result

    for component in components:
        component_identifier_json = json.dumps(component['componentIdentifier'])
        component_display_name = component['displayName']
        effective_licenses = component['licenseLegalData']['effectiveLicenses']
        effective_threat_groups = set()
        highest_effective_threat_group = ''

        if component['licenseLegalData']['highestEffectiveLicenseThreatGroup'] is not None:
            highest_effective_threat_group = component['licenseLegalData']['highestEffectiveLicenseThreatGroup'][
                'licenseThreatGroupName']

        # This looks strange, but what we're doing here is first checking to see if it is a single license
        # by looking at the license_data mapping. If it isn't a single license then we use the multi-license
        # mapping to convert the multi-license into an array of single licenses, which we then map using
        # the license data mapping.
        for effective_license in effective_licenses:
            if effective_license in license_data:
                effective_threat_groups.add(license_data[effective_license])
            elif effective_license in multi_license_data:
                for single_license in multi_license_data[effective_license]:
                    if single_license in license_data:
                        effective_threat_groups.add(license_data[single_license])

        result.append([component_identifier_json, component_display_name, ', '.join(effective_licenses),
                       ', '.join(effective_threat_groups),
                       highest_effective_threat_group])

    return result


def __get_legal_data(applications, server_url, username, password):
    """ Returns a mapping of application public ID to a listing of component name, effective licenses, threat groups for those licenses, and the highest effective threat group."""
    result = {}

    for application in applications:
        legal_data = __request(server_url, LEGAL_ENDPOINT.format(application), username, password)
        license_data = __parse_license_data(legal_data['licenseLegalMetadata'])
        multi_license_data = __parse_multi_license_data(legal_data['licenseLegalMetadata'])
        component_data = __parse_component_data(license_data, multi_license_data, legal_data['components'])
        result[application] = component_data

    return result


def __write_tsv(legal_data, output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        header_row = ['application_name', 'component_identifier', 'component_name', 'effective_licenses',
                      'effective_threat_groups', 'highest_effective_threat_group']
        writer = csv.writer(csvfile, delimiter='\t', quoting=csv.QUOTE_MINIMAL)

        writer.writerow(header_row)

        for application in legal_data:
            for component_row in legal_data[application]:
                component_row.insert(0, application)
                writer.writerow(component_row)


def __parse_args():
    parser = argparse.ArgumentParser(
        description='Connects to IQ and uses the APIs to create a CSV that contains the applications, component names, licenses, and the LTG of those licenses.')
    parser.add_argument('-s', dest='server_url',
                        default='http://localhost:8070', help='URL of IQ instance.', required=True)
    parser.add_argument('-u', dest='username',
                        default='admin', help='IQ user\'s username.', required=True)
    parser.add_argument('-p', dest='password',
                        default='password', help='IQ user\'s password.', required=True)
    parser.add_argument('-c', dest='categories', nargs='+',
                        help='An optional list of application categories to use as a filter for applications.')
    parser.add_argument('-o', dest='output_file',
                        default='output.tsv', help='Output filepath.')
    return parser.parse_args()


if __name__ == "__main__":
    args = __parse_args()
    applications = __get_applications(args.server_url, args.username, args.password, args.categories)
    legal_data = __get_legal_data(applications, args.server_url, args.username, args.password)
    __write_tsv(legal_data, args.output_file)
