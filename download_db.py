import os

import requests
import re
from os import listdir
from os.path import isfile, join
import zipfile
import json
import pathlib
import wget


class DownloadDb:
    cve_dict = {}

    def __init__(self):
        if 'nvd' not in listdir():
            pathlib.Path('nvd').mkdir(parents=True, exist_ok=True)
            self.download_all_zips_files()

        files = [f for f in listdir("nvd/") if isfile(join("nvd/", f))]
        files.sort()
        for file_name in files:
            year = file_name[11:15]
            archive = zipfile.ZipFile(join("nvd/", file_name), 'r')
            jsonfile = archive.open(archive.namelist()[0])
            self.cve_dict[year] = json.loads(jsonfile.read())
            jsonfile.close()

    @staticmethod
    def download_all_zips_files():
        """
       This function, perform get requests from the NVD site for all vulnerabilities data files which finish with ".json.zip"
       Finally the function writes all the files to NVD folder on the local disk
        :return:
        """
        r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
        for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip", r.text):
            r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
            with open("nvd/" + filename, 'wb') as f:
                for chunk in r_file:
                    f.write(chunk)


def download_file():
    # importing the requests module
    import requests
    print('Downloading started')
    url = 'https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip'

    # Downloading the file by sending the request to the URL
    req = requests.get(url)

    # Split URL to get the file name
    filename = url.split('/')[-1]

    # Writing the file to the local file system
    with open(filename, 'wb') as output_file:
        output_file.write(req.content)
    print('Downloading Completed')

    #url = 'https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip'
    #wget.download(url)
    #r_file = requests.get(url, stream=True)
    # with open(r_file, 'wb') as f:
    #     for chunk in r_file:
    #         f.write(chunk)


def unzip_file(file_name, directory_to_extract=None):
    with zipfile.ZipFile(file_name, 'r') as zip_ref:
        zip_ref.extractall(directory_to_extract)
    os.remove(file_name)  # removing the .zip file


