import requests
import re
from os import listdir
from os.path import isfile, join
import zipfile
import json


def downloadAllZipsFiles():
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


def getCVE_Dict(year: str) -> {}:
    """

    :param year: The function creates CVE dictionary according to the request year
    :return: CVE dictionary
    """
    cve_dict = {}
    files = [f for f in listdir("nvd/") if isfile(join("nvd/", f))]
    files.sort()
    for file in files:
        if year in file:
            archive = zipfile.ZipFile(join("nvd/", file), 'r')
            jsonfile = archive.open(archive.namelist()[0])
            cve_dict = json.loads(jsonfile.read())
            jsonfile.close()
    return cve_dict


def downloadAllZipFiles(SourceUrl, FileName):
    r = requests.get(SourceUrl)
    for filename in re.findall(FileName, r.text):
        r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
        with open("nvd/" + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)