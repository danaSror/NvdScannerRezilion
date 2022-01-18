import json
import os
from client.codes.download_db import DownloadDb
from client.codes.installed_softwares import InstalledSoftware
from client.codes.searchEngine import SearchEngineBuilder, CpeSwFitter
from client.codes.xmlParser import CpeXmlParser
from client.codes.cve_parser import CveParser
import socket


class Agent:

    def __init__(self):
        self.result = ""
        self.result_dict = {}
        self.computer_name = socket.gethostname()

    def cpe_handle(self):
        self.result += "Running the searcher - match for each software its cpe...\n"
        if not os.path.isfile('official-cpe-dictionary_v2.3.xml'):
            DownloadDb.download_file()
            DownloadDb.unzip_file('official-cpe-dictionary_v2.3.xml.zip', directory_to_extract=None)
            self.result += 'Complete process of downloading cpe-dictionary\n'

        if not os.path.isfile("parsed_xml.csv"):
            a = CpeXmlParser('official-cpe-dictionary_v2.3.xml')
            a.csv_creator('official-cpe-dictionary_v2.3.xml')
            self.result += "Complete process of create cpe parsed xml\n"

    @staticmethod
    def run_searcher():
        searcher = SearchEngineBuilder()
        searcher.create_models("parsed_xml.csv", "cosin")
        cpe_sw_fitter = CpeSwFitter("parsed_xml.csv", "cosin")
        df = cpe_sw_fitter.fit_all(1)
        return df

    def computer_software_handle(self):
        self.result += "Getting installed software....\n"
        if not os.path.isfile("registry_data.json"):
            installed_software = InstalledSoftware()
            installed_software.dump_software_lst_to_json(["Publisher", 'DisplayVersion', 'DisplayName'])

    def run(self):
        # download file of all installed software on computer
        self.computer_software_handle()

        # running the searcher - match for each software its cpe
        self.cpe_handle()
        software_to_cpe_match_df = self.run_searcher()  # df columns : ["registry_sw", "cpe_items", "titles"]

        # create cpe dictionary which match for each cpe a list of cves
        self.result += "Create cve match for each cpe detected\n"
        cv = CveParser()
        cpe_dictionary = cv.get_cpe_dict()

        # search the result cpe in the cpe-cve dictionary and return for each cpe a cve list
        for row in software_to_cpe_match_df.itertuples(index=True, name='Pandas'):
            software_name = row.registry_sw
            cpe_item = row.cpe_items
            self.result_dict[software_name] = {cpe_item: []}
            for key in cpe_dictionary.keys():
                if cpe_item[5:] in key:
                    self.result += "*********************************************************************************\n"
                    self.result += "Software name: " + software_name + "\n"
                    self.result += "Vulnerabilities results for this software:\n"
                    self.result += "\n"
                    for cve_identifier in cpe_dictionary[key]:
                        cve = cv.get_cve_by_identifier(cve_identifier)
                        self.result_dict[software_name][cpe_item].append(cve.cve_to_dict())
                        self.result += cve.cve_to_string() +"\n"
                    self.result += "\n"



if __name__ == '__main__':
    agent = Agent()
    agent.run()
    print(json.dumps(agent.result_dict, indent = 4))
