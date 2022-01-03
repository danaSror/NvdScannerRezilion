import os
import download_db
from installed_softwares import InstalledSoftware
from searchEngine import SearchEngineBuilder, CpeSwFitter
from xmlParser import CpeXmlParser
from cve_parser import CveParser


class Agent:
    def __init__(self):
        pass

    def cve_handle(self):
        pass

    @staticmethod
    def cpe_handle():
        if not os.path.isfile('official-cpe-dictionary_v2.3.xml'):
            download_db.download_file()
            download_db.unzip_file('official-cpe-dictionary_v2.3.xml.zip', directory_to_extract=None)
            print('Complete process of downloading cpe-dictionary')

        if not os.path.isfile("parsed_xml.csv"):
            a = CpeXmlParser('official-cpe-dictionary_v2.3.xml')
            a.csv_creator('official-cpe-dictionary_v2.3.xml')
            print("Complete process of create cpe parsed xml")

    @staticmethod
    def run_searcher():
        searcher = SearchEngineBuilder()
        searcher.create_models("parsed_xml.csv", "cosin")
        cpe_sw_fitter = CpeSwFitter("parsed_xml.csv", "cosin")
        df = cpe_sw_fitter.fit_all(1)
        return df

    @staticmethod
    def computer_software_handle():
        if not os.path.isfile("registry_data.json"):
            installed_software = InstalledSoftware()
            installed_software.dump_software_lst_to_json(["Publisher", 'DisplayVersion', 'DisplayName'])

    def match_cve_to_cpe(self):
        pass

    def run(self) :
        # TODO - download file of all installed software on computer
        self.computer_software_handle()

        # TODO - running the searcher - match for each software its cpe
        self.cpe_handle()
        software_to_cpe_match_df = self.run_searcher()  # df columns : ["registry_sw", "cpe_items", "titles"]

        # TODO - create cpe dictionary which match for each cpe a list of cves
        cv = CveParser()
        cpe_dictionary = cv.get_cpe_dict()

        # TODO - search the result cpe in the cpe-cve dictionary and return for each cpe a cve list
        for row in software_to_cpe_match_df.itertuples(index=True, name='Pandas'):
            software_name = row.registry_sw
            cpe_item = row.cpe_items
            for key in cpe_dictionary.keys():
                if cpe_item[5:] in key:
                    print("*********************************************************************************************")
                    print("Software name: "+software_name)
                    print("Vulnerabilities results for this software:")
                    print()
                    for cve_identifier in cpe_dictionary[key]:
                        cve = cv.get_cve_by_identifier(cve_identifier)
                        print(cve.cve_to_string())
                        print()
                    print()




if __name__ == '__main__':
    agent = Agent()
    agent.run()