import download_db
import json
from cve import Cve
from dataclasses import dataclass


@dataclass()
class CveParser:
    cve_collections_for_all_years = {}

    def __init__(self):
        self.cve_collections_for_all_years = download_db.DownloadDb().cve_dict

    def get_cve_collection_for_specific_year(self, year: str) -> []:
        """

        :param year:
        :return: list of all cve for the given year. Each cell in the returning list is cve object
        """
        cve_collection = []
        cve_dict = self.cve_collections_for_all_years[year]
        for cve_json_presentation in cve_dict['CVE_Items']:
            cve_id = cve_json_presentation['cve']['CVE_data_meta']['ID']
            assigner = None
            if 'ASSIGNER' in cve_json_presentation['cve']['CVE_data_meta'].keys():
                assigner = cve_json_presentation['cve']['CVE_data_meta']['ASSIGNER']
            description = cve_json_presentation['cve']['description']['description_data'][0]['value']
            severity = None
            if len(cve_json_presentation['impact']) > 1:
                severity = self.extract_severity(cve_json_presentation['impact'])
            cve = Cve(cve_id, assigner, description, severity)
            cve_collection.append(cve)

        return cve_collection

    def write_all_cve_collection_for_specific_year_to_file(self, year: str):
        """

        :param year:
        :return: This function write all the cve objects of a given year to Json file named : "cve_collections_for_{0}.json"
        """
        cve_collection = self.get_cve_collection_for_specific_year(year)
        cve_json_collection = []
        for cve in cve_collection:
            cve_json = {
                "identifier": cve.identifier,
                "assigner": cve.assigner,
                "description": cve.description,
                "severity": cve.severity
            }
            cve_json_collection.append(cve_json)
        json_object = json.dumps(cve_json_collection, indent=4)
        with open("cve_collections_for_{0}.json".format(year), "w") as outfile:
            outfile.write(json_object)

    def get_cpe_dict(self):
        all_cves_for_cpe = {}
        all_cve_years = self.cve_collections_for_all_years
        for year in range(2002,2021):
            all_cve_for_specific_year = all_cve_years[str(year)]
            for json_cve in all_cve_for_specific_year['CVE_Items']:
                if len(json_cve['configurations']['nodes']) > 0:
                    cpe_list_of_this_cve = json_cve['configurations']['nodes'][0]['cpe_match']
                    for cpe in cpe_list_of_this_cve:
                        cpe_key = cpe['cpe23Uri'][8:]
                        if cpe_key in all_cves_for_cpe.keys():
                            all_cves_for_cpe[cpe_key].append(json_cve['cve']['CVE_data_meta']['ID'])
                        else:
                            all_cves_for_cpe[cpe_key] = []
                            all_cves_for_cpe[cpe_key].append(json_cve['cve']['CVE_data_meta']['ID'])
        return all_cves_for_cpe

    def get_cve_by_identifier(self, identifier: str):
        identifier_list = identifier.split("-")
        cve_year = identifier_list[1] #'CVE-1999-0001'
        for jsov_cve in self.cve_collections_for_all_years[cve_year]['CVE_Items']:
            if jsov_cve['cve']['CVE_data_meta']['ID'] == identifier:
                assigner = None
                if 'ASSIGNER' in jsov_cve['cve']['CVE_data_meta'].keys():
                    assigner = jsov_cve['cve']['CVE_data_meta']['ASSIGNER']
                description = jsov_cve['cve']['description']['description_data'][0]['value']
                severity = None
                if len(jsov_cve['impact']) > 1:
                    severity = self.extract_severity(jsov_cve['impact'])
                cve = Cve(identifier, assigner, description, severity)
        return cve



    @staticmethod
    def extract_severity(impact: []) -> str:
        if len(impact) > 1:
            severity = impact['baseMetricV3']['cvssV3']['baseSeverity']
        else:
            severity = impact['baseMetricV2']['severity']

        return severity


if __name__ == '__main__':
    dict = CveParser().get_cve_collection_for_specific_year("2021")
    print()