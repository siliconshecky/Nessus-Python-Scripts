#!/usr/bin/env python
#
# Original Author  -- Alexander Sferrella
# Originally Created -- 13 September, 2017
# Forked and Modified by Michael Kavka
# Modification Date 12 December, 2019

import argparse
import io
import csv
from csv import QUOTE_ALL
import re
import time
import xml.etree.ElementTree as ET

# CSV and Nessus headers
csvHeaders = ['CVSS Score', 'IP', 'FQDN', 'OS', 'Port', 'Vulnerability', 'Risk', 'Description', 'Exploit Available', 'Proof', 'Solution', 'See Also', 'CVE', 'Plugin ID'] #headers for the CSV
nessusFields = ['cvss_base_score', 'host-ip', 'host-fqdn', 'operating-system', 'port', 'plugin_name', 'risk_factor', 'description', 'exploit_available', 'plugin_output', 'solution', 'see_also', 'cve', 'pluginID'] # headers of the nessus file. These are pulled from the XML. Order here must match up to the CSV headers you want for each item.

# Create output CSV file
def createCSV(nessus_file):
    # Take the input file name and strip it down for recombinining into a new filename that has month and date in the file name for easy searching
    str_file = str(nessus_file)
    str_file = re.sub(r'\.nessus', '', str_file)
    str_file = re.sub(r"\[\'", "", str_file)
    str_file = re.sub(r"\'\]", "", str_file)
    basefile = re.sub(r'\d+', '', str_file)
    outFile = open(basefile + time.strftime("%m_%Y") + '.csv', "w", newline='') # create the CSV file and open it for writing along with removing blank lines from the CSV
    csvWriter = csv.DictWriter(outFile, csvHeaders, quoting=QUOTE_ALL) # set the headers
    csvWriter.writeheader() 
    return csvWriter

# Clean values from nessus report
def getValue(rawValue):
    cleanValue = rawValue.replace('\n', ' ').strip(' ')
    if len(cleanValue) > 32000:
        cleanValue = cleanValue[:32000] + ' [Text Cut Due To Length]'
    return cleanValue

# Helper function for handleReport()
def getKey(rawKey):
    return csvHeaders[nessusFields.index(rawKey)] # lines up the Nessus headres with the CSV headers

# Handle a single report item
def handleReport(report):
    findings = []
    reportHost = dict.fromkeys(csvHeaders, '')
    for item in report:
        if item.tag == 'HostProperties':
            for tag in (tag for tag in item if tag.attrib['name'] in nessusFields):
                reportHost[getKey(tag.attrib['name'])] = getValue(tag.text)
        if item.tag == 'ReportItem': # this will parse out items that are in the tag <Report item>
            reportRow = dict(reportHost)
            reportRow['Port'] = item.attrib['port']
            reportRow['Vulnerability'] = item.attrib['pluginName']
            reportRow['Plugin ID'] = item.attrib['pluginID']
            for tag in (tag for tag in item if tag.tag in nessusFields):
                reportRow[getKey(tag.tag)] = getValue(tag.text)
            # Clean up - Mike G
            # if reportRow['CVSS Score'] != "": # if you want only items with CVSS scores, uncomment this and tab the findings line below to be under it. If this line is commented out and you tab the line below under the for statement above you will get 4 lines for each plugin output.
            findings.append(reportRow)
    return findings

# Get files 
def handleArgs():
    aparser = argparse.ArgumentParser(description='Converts Nessus scan findings from XML to a CSV file.', usage="\n./parse-nessus.py input.nessus\nAny fields longer than 32,000 characters will be truncated.")
    aparser.add_argument('nessus_xml_files', type=str, nargs='+', help="nessus xml file to parse")
    args = aparser.parse_args()
    nessus_file = args.nessus_xml_files
    return nessus_file

# Main
if __name__ == '__main__':
    reportRows = []
    for nessusScan in handleArgs():
        try:
            scanFile = ET.parse(nessusScan)
        except IOError:
            print("Could not find file \"" + nessusScan + "\"")
            exit()
        xmlRoot = scanFile.getroot()
        for report in xmlRoot.findall('./Report/ReportHost'):
            findings = handleReport(report)
            reportRows.extend(findings)
    nessus_file = handleArgs()
    createCSV(nessus_file).writerows(reportRows)
