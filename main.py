import os

import get_files_programfiles
from cve_parser import CveParser
from installed_softwares import InstalledSoftware
from searchEngine import SearchEngineBuilder, CpeSwFitter
from xmlParser import CpeXmlParser
import download_db
from cve_parser import CveParser

if __name__ == '__main__':
    cv = CveParser()
    cve_dict = cv.get_cpe_and_cve_dict()
    print()


    if not os.path.isfile('official-cpe-dictionary_v2.3.xml'):
        download_db.download_file()
        download_db.unzip_file('official-cpe-dictionary_v2.3.xml.zip', directory_to_extract=None)

    if not os.path.isfile("registry_data.json"):
        i_s = InstalledSoftware()
        i_s.dump_software_lst_to_json(["Publisher", 'DisplayVersion', 'DisplayName'])

    if not os.path.isfile("parsed_xml.csv"):
        a = CpeXmlParser('official-cpe-dictionary_v2.3.xml')
        a.csv_creator('official-cpe-dictionary_v2.3.xml')

    # if not os.path.isfile("retrieved_cosin.csv"):
    sim_func_names_list = ["cosin"]
    for func in sim_func_names_list:
        search_builder = SearchEngineBuilder()
        search_builder.create_models("parsed_xml.csv", func)
        cpe_sw_fitter = CpeSwFitter("parsed_xml.csv", func)
        cpe_sw_fitter.fit_all(5)
    print("end")