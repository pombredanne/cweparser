import xmltodict
import json
from dotted_dict import DottedDict as ddict
undefined = "undefined"

def write_xmpl_to_json_file():
    with open('cwe.xml', 'r') as fp:
        xml = fp.read()
        j = xmltodict.parse(xml)
        with open('cwec.json', 'w') as fp:
            json.dump(j, fp)

def load_json_from_file():
    with open('cwec.json', 'r') as fp:
        return json.load(fp)

json_database = load_json_from_file()

Weakness_Catalog = json_database.get("Weakness_Catalog", {})

Weaknesses_Section = Weakness_Catalog.get("Weaknesses", {}).get("Weakness", [])
Categories_Section = Weakness_Catalog.get("Categories", {}).get("Category", [])
Views_Section = Weakness_Catalog.get("Views", {}).get("View", [])
External_References_Section = Weakness_Catalog.get("External_References", {}).get("External_Reference", [])

# ############################################################################
#  Weaknesses
# ############################################################################


def recursive_description_dict_to_text(dictionary):
    text = ""
    keys = dictionary.keys()
    for key in keys:
        if isinstance(dictionary[key], str):
            if "@style" not in key:
                text += dictionary[key] + '\n'
        elif isinstance(dictionary[key], dict):
            text += recursive_description_dict_to_text(dictionary[key])
        elif isinstance(dictionary[key], list):
            for k in dictionary[key]:
                if isinstance(k, str):
                    if "@style" not in key:
                        if ":li" in key:
                            text += "- " + k + '\n'
                        else:
                            text += k + '\n'
                elif isinstance(k, dict):
                    text += recursive_description_dict_to_text(k)
    return text

def Parse_Extended_Description(Extended_Description):
    if isinstance(Extended_Description, str):
        return Extended_Description
    elif isinstance(Extended_Description, list):
        text = ""
        for ed in Extended_Description:
            text += ed + '\n'
    elif isinstance(Extended_Description, dict):
        return recursive_description_dict_to_text(Extended_Description)
    return undefined

def Parse_Related_Weaknesses(Related_Weaknesses):
    Related_Weakness = []
    rw = Related_Weaknesses.get("Related_Weakness", [])
    if isinstance(rw, dict):
        rw = [rw]
    for r in rw:
        Related_Weakness.append(
            dict(
                Nature=r.get("@Nature", undefined),
                CWE_ID=r.get("@CWE_ID", undefined),
                ViewID=r.get("@View_ID", undefined),
                Ordinal=r.get("@Ordinal", undefined)
            )
        )
    return Related_Weakness

def Parse_Alternate_Terms(Alternate_Terms):
    Alternate_Term = []
    at = Alternate_Terms.get("Alternate_Term", [])
    if isinstance(Alternate_Term, list):
        at = [at]
    for a in at:
        description = a.get("Description", {})
        if isinstance(description, dict):
            dscr = recursive_description_dict_to_text(description)
        elif isinstance(description, str):
            dscr = description
        Alternate_Term.append(
            dict(
                Term=a.get("Term", undefined),
                Description=dscr
            )
        )
    return Alternate_Term


def Parse_Weaknesses(Weaknesses_Section):
    Weaknesses_list = Weaknesses_Section.get("Weakness", [])
    for One_Weakness in Weaknesses_list:
        Weakness = ddict()
        Weakness.ID = One_Weakness.get("@ID", undefined)
        Weakness.Name = One_Weakness.get("@Name", undefined)
        Weakness.Abstraction = One_Weakness.get("@Abstraction", undefined)
        Weakness.Structure = One_Weakness.get("@Structure", undefined)
        Weakness.Status = One_Weakness.get("@Status", undefined)
        Weakness.Description = One_Weakness.get("Description", undefined)
        Weakness.Extended_Description = Parse_Extended_Description(One_Weakness.get("Extended_Description", {}))
        Weakness.Related_Weaknesses = Parse_Related_Weaknesses(One_Weakness.get("Related_Weaknesses", {}))
        Weakness.Alternate_Terms = Parse_Alternate_Terms(One_Weakness.get("Alternate_Terms", {}))
    pass

print("Parse Weaknesses")
# Weaknesses = Parse_Weaknesses(Weaknesses_Section)




# - Views

# View_Structure
# View_Objective
# View_Audience
# Relationships
# Content_History
# Categories

# - Categories
# ID
# Name
# Status
# Description
# Relationship
# Relationship_Notes
# Theoretical_Notes
# Research_Gaps
# Weakness_Ordinalities

# Applicable_Platforms

# Detection_Methods

# Maintenance_Notes

# Time_of_Introduction

# Likelihood_of_Exploit

# Common_Consequences

# Potential_Mitigations

# Causal_Nature

# Demonstrative_Examples

# Affected_Resources

# Content_History

# References

# Taxonomy_Mappings

# White_Box_Definitions

# Related_Attack_Patterns

# 6285


# - Weaknesses

# - Compound_Elements

