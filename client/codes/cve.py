from dataclasses import dataclass


@dataclass
class Cve:
    identifier: int
    assigner: str
    description: str
    severity: str

    def __init__(self, identifier, assigner, description, severity):
        self.identifier = identifier
        self.assigner = assigner
        self.description = description
        self.severity = severity

    def cve_to_string(self) -> str:
        return """CVE details : \nIdentifier: {0}\nAssigner: {1}\nDescription: {2}\nSeverity: {3}""".format(self.identifier, self.assigner, self.description, self.severity)

    def cve_to_dict(self):
        return {
            "identifier": self.identifier,
            "assigner": self.assigner,
            "description": self.description,
            "severity": self.severity
        }


