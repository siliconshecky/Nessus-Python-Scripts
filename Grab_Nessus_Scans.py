#!/usr/bin/env python

# This will go out and grab whatever reports you need from your Nessus scanner
# Along with showing the different folders and UUIDs, you can us all to grab them all

import requests, json, sys, os, getpass, time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Turn off certificate warnings

requests.packages.urllib3.disable_warnings(InsecureRequestWarning) 

url = '<your Nessus URL>'
verify = False
token = ''
username = ''
password = ''

accessKey = "<Get this from your Nessus server web interface>"
secretKey = "<Generate this from your Nessus server Web interface>"
headers = {"Content-type": "application/json", "X-ApiKeys": "accessKey=" + accessKey + "; secretKey=" + secretKey}

def build_url(resource):
        return '{0}{1}'.format(url, resource)


def connect(method, resource, data=None):
        headers = {"Content-type": "application/json", "X-ApiKeys": "accessKey=" + accessKey + "; secretKey=" + secretKey}
        data = json.dumps(data)
        if method == 'POST':
                r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'PUT':
                r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'DELETE':
                r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
                return
        else:
                r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)

        if r.status_code != 200:
                e = r.json()
                print e['error']
                sys.exit()

        if 'download' in resource:
                return r.content
        else:
                return r.json() 

def list_scan():
        data = connect('GET', '/scans')
        return data

def count_scan(scans, folder_id):
        count = 0
        for scan in scans:
                if scan['folder_id']==folder_id: count=count+1
        return count

def print_scans(data):
        for folder in data['folders']:
                print("\\{0} - ({1})\\".format(folder['name'], count_scan(data['scans'], folder['id'])))
                for scan in data['scans']:
                        if scan['folder_id']==folder['id']:
                                print("\t\"{0}\" - uuid: {1}".format(scan['name'].encode('utf-8'), scan['uuid']))

def export_status(scan_id, file_id):
        data = connect('GET', '/scans/{0}/export/{1}/status'.format(scan_id, file_id))
        return data['status'] == 'ready'

def get_folder_id(serch_folder_name, data):
        folder_id = 0;
        for folder in data['folders']:
                if folder['name']==serch_folder_name:
                        folder_id = folder['id']
                        break
        return folder_id

def export_folder(folder_name, data):
        if folder_name == 'All' or folder_name == 'all':
                for scan in data['scans']:
                        file_id = export(scan['id'])
                        download(scan['name'], scan['id'], file_id,os.path.join(os.getcwd(),folder_name))
        else:
                folder_id = get_folder_id(folder_name,data)
                if count_scan(data['scans'], folder_id)==0:
                        print "This folder does not contain reports"
                        return
                if folder_id!=0:
                        for scan in data['scans']:
                                if scan['folder_id'] == folder_id:
                                        file_id = export(scan['id'])
                                        download(scan['name'], scan['id'], file_id, os.path.join(os.getcwd(),folder_name))
                else:
                        print "No such folder..."
                        
                        
        
def export(scan_id):
        data = {'format': 'nessus'}
        data = connect('POST', '/scans/{0}/export'.format(scan_id), data=data)
        file_id = data['file']
        while export_status(scan_id, file_id) is False:
                time.sleep(5)
        return file_id

def download(report_name, scan_id, file_id, save_path):
        if not(os.path.exists(save_path)): os.mkdir(save_path)
        data = connect('GET', '/scans/{0}/export/{1}/download'.format(scan_id, file_id))
        file_name = 'nessus_{0}_{1}.nessus'.format(report_name.encode('utf-8'), file_id)

        print('Saving scan results to {0}'.format(file_name))
        with open(os.path.join(save_path,file_name), 'w') as f:
                f.write(data)

print("List of reports...")
rep_list = list_scan()
print_scans(rep_list)

print("Exporting reports...")
exp_folder_name = raw_input('Input folder name to export (type "all" to export all reports): ')
export_folder(exp_folder_name, rep_list)