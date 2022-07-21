"""
Purpose:    Get CVSSv3 metrics for specified CVEs from the NIST National Vulnerability Database API
            Useful tool for Vulnerability Management
Author: Kassidy Hall (technodivergent)
Date: July 2022
"""
import json
import argparse
import csv
import requests
import os.path
import config
from ratelimit import limits, RateLimitException, sleep_and_retry

ONE_MIN = 60
MAX_CPM = 100

@sleep_and_retry
@limits(calls=MAX_CPM, period=ONE_MIN)
def get_json(cve_id: str) -> json:
    """ Fetch JSON data from the NVD """
    API_KEY = config.API_KEY
    try:
        url = 'http://services.nvd.nist.gov/rest/json/cve/1.0/' + cve_id + '?apiKey='+ API_KEY
        print(url)
        resp = requests.get(url)
    except requests.exceptions.RequestException as e:
        raise SystemExit('Unable to establish connection: %s' % e)
    return resp.json()

def get_cvss3_data(json: json) -> dict:
    """ Extract the CVSSv3 data from JSON and store it as a dictionary """
    try:
        result = json['result']['CVE_Items'][0]
        cvss3_dict = {}
        # impact
        cvss3_json = result['impact']['baseMetricV3']['cvssV3']
        cvss3_dict['Attack_Vector']        = cvss3_json['attackVector'].title()
        cvss3_dict['Attack_Complexity']    = cvss3_json['attackComplexity'].title()
        cvss3_dict['Privileges_Required']  = cvss3_json['privilegesRequired'].title()
        cvss3_dict['User_Interaction']     = cvss3_json['userInteraction'].title()
        cvss3_dict['Scope']               = cvss3_json['scope'].title()
        cvss3_dict['Confidentiality_Impact'] = cvss3_json['confidentialityImpact'].title()
        cvss3_dict['Integrity_Impact']     = cvss3_json['integrityImpact'].title()
        cvss3_dict['Availability_Impact']  = cvss3_json['availabilityImpact'].title()
        cvss3_dict['Base_Score']           = cvss3_json['baseScore']
        cvss3_dict['Base_Severity']        = cvss3_json['baseSeverity'].title()
    except KeyError:
        cvss3_dict = {}
    return cvss3_dict

def save_csv(filename: str, dictionary: dict) -> None:
    """ Save CVSSv3 dictionary as a CSV file """
    file_exists = os.path.isfile(filename)

    try:
        with open(filename, 'a') as fh:
            headers = dictionary.keys()
            csv_writer = csv.DictWriter(fh, delimiter=',', lineterminator='\n', fieldnames=headers)

            if not file_exists:
                csv_writer.writeheader()
            csv_writer.writerow(dictionary)
    except csv.Error as e:
        raise SystemExit('Unable to write CSV to file: %s' % e)
    
def main() -> None:
    """ Main Method """
    argp = argparse.ArgumentParser(description='Request CVE details from National Vulnerability Database')
    
    group = argp.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-c', '--cve-id',
        type=str,
        default=None,
        help='Specify the requested CVE')
    group.add_argument(
        '-f', '--cve-list',
        type=argparse.FileType('r'),
        default=None,
        help='Specify the requested CVEs from a list file (one CVE entry per line)')
    args = argp.parse_args()

    cve_list = []

    # if single CVE requested, append it to a list, otherwise import the list from a file
    # NOTE: Format of list must be a single CVE entry per line
    if(args.cve_list is None):
        cve_list.append(args.cve_id)
    else:
        cve_list = args.cve_list.read().splitlines()

    # pull CVSSv3 data for one or more CVEs
    for cve_id in cve_list:
        json = get_json(cve_id)
        cvssv3_data = get_cvss3_data(json)
        save_csv('cvss_vectors.csv', cvssv3_data)

if __name__ == '__main__':
    main()