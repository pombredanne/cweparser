# -*- coding: utf-8 -*-
import os
import sys
import re
import xmltodict
import json
import peewee
from example import database

import peewee
from datetime import datetime
from playhouse.postgres_ext import ArrayField
from playhouse.postgres_ext import JSONField

database = peewee.PostgresqlDatabase(
    database="updater_db",
    user="admin",
    password="123",
    host="localhost",
    port="5432"
)

undefined = "undefined"

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

DEBUG = False

def write_xmpl_to_json_file():
    with open('cwe.xml', 'r') as fp:
        xml = fp.read()
        j = xmltodict.parse(xml)
        with open('cwec.json', 'w') as fp:
            json.dump(j, fp)

def load_json_from_file():
    with open('cwec.json', 'r') as fp:
        return json.load(fp)


if not DEBUG:
    json_database = load_json_from_file()
else:
    json_database = database

Weakness_Catalog = json_database.get("Weakness_Catalog", {})

Weaknesses_Section = Weakness_Catalog.get("Weaknesses", {}).get("Weakness", [])
Categories_Section = Weakness_Catalog.get("Categories", {}).get("Category", [])
Views_Section = Weakness_Catalog.get("Views", {}).get("View", [])
External_References_Section = Weakness_Catalog.get("External_References", {}).get("External_Reference", [])

def Only_Digits(s):
    return re.sub("\D\?", "", s)

def Make_CWE_Number(CWE_String):
    return "CWE-" + Only_Digits(CWE_String)

def Make_CWE_Array(CWE_Array_To_Clear):
    if isinstance(CWE_Array_To_Clear, list):
        return list(map(Make_CWE_Number, CWE_Array_To_Clear))
    return []

def Make_CAPEC_Number(CAPEC_String):
    return "CAPEC-" + Only_Digits(CAPEC_String)

def Make_CAPEC_Array(CAPEC_Array_To_Clear):
    if isinstance(CAPEC_Array_To_Clear, list):
        return list(map(Make_CAPEC_Number, CAPEC_Array_To_Clear))
    return []

def Flatter_Unique_Array(array):
    if isinstance(array, list):
        res = []
        for a in array:
            if isinstance(a, str):
                res += [a]
            elif isinstance(a, list):
                res += a
        return list(set(res))
    if isinstance(array, str):
        return [array]
    return []

def CT(text):
    return text.replace('’', "'")

def Convert_Description_Dict_To_Text(dictionary):
    text = ""
    if isinstance(dictionary, dict):
        keys = dictionary.keys()
        if "xhtml:p" in keys:
            xhtml_p = dictionary["xhtml:p"]
            if isinstance(xhtml_p, str):
                text += xhtml_p
            if isinstance(xhtml_p, list):
                text += "\n".join(xhtml_p)
        if "xhtml:div" in keys:
            xhtml_div = dictionary["xhtml:div"]
            if isinstance(xhtml_div, dict):
                if "xhtml:div" in xhtml_div.keys():
                    xhtml_div_2 = xhtml_div["xhtml:div"]
                    if isinstance(xhtml_div_2, str):
                        xhtml_div_2 = [xhtml_div_2]
                    text += "\n".join(xhtml_div_2)

                if "xhtml:ul" in xhtml_div.keys():
                    xhtml_ul = xhtml_div["xhtml:ul"]
                    if "xhtml:li" in xhtml_ul:
                        xhtml_li = xhtml_ul["xhtml:li"]
                        if isinstance(xhtml_li, str):
                            xhtml_li = [xhtml_li]
                        text += '\n'
                        for xhtml_li_element in xhtml_li:
                            if isinstance(xhtml_li_element, str):
                                text += '- ' + xhtml_li_element + '\n'
                            elif isinstance(xhtml_li_element, dict):
                                if "xhtml:b" in xhtml_li_element:
                                    xhtml_b = xhtml_li_element.get("xhtml:b", "")
                                    text += xhtml_b + '\n'
                                if "#text" in xhtml_li_element:
                                    text += xhtml_li_element.get("#text", "")

                if "xhtml:ol" in xhtml_div.keys():
                    num = 1
                    xhtml_ol = xhtml_div["xhtml:ol"]
                    if "xhtml:li" in xhtml_ol:
                        xhtml_li = xhtml_ol["xhtml:li"]
                        if isinstance(xhtml_li, str):
                            xhtml_li = [xhtml_li]
                        text += '\n'
                        for x in xhtml_li:
                            text += str(num) + '. ' + x + '\n'
                            num += 1
        
        if "xhtml:ul" in keys:
            text += '\n'
            xhtml_ul = dictionary["xhtml:ul"]
            for xhtml_ul_element in xhtml_ul:
                if isinstance(xhtml_ul_element, dict):
                    if "xhtml:li" in xhtml_ul_element:
                        xhtml_li = xhtml_ul_element["xhtml:li"]
                        if isinstance(xhtml_li, list):
                            for xhtml_li_element in xhtml_li:
                                if isinstance(xhtml_li_element, str):
                                    text += xhtml_li_element + '\n'
                                elif isinstance(xhtml_li_element, dict):
                                    if "xhtml:b" in xhtml_li_element:
                                        text += xhtml_li_element["xhtml:b"] + '\n'
                                    if "#text" in xhtml_li_element:
                                        s = xhtml_li_element["#text"]
                                        s = re.sub(r'\s+', ' ', s)
                                        text += s + '\n'
    elif isinstance(dictionary, str):
        text = dictionary
    return text

def Convert_List_Of_Strings_To_One_String(String_Or_List):
    text = ""
    if isinstance(String_Or_List, str):
        return String_Or_List
    if isinstance(String_Or_List, list):
        for s in String_Or_List:
            text += s + '\n'
    return text

def CWE_Match(String):
    if isinstance(String, str):
        return re.findall(r"CWE-[0-9]{1,4}", String)
    return []

def Scan_Related_Weakness_For_CWE(Related_Weakness):
    if Related_Weakness is None:
        return []
    if isinstance(Related_Weakness, list):
        base = []
        for rw in Related_Weakness:
            if "CWE_ID" in rw:
                base.append(rw["CWE_ID"])
    return Make_CWE_Array(Flatter_Unique_Array(base))

def Scan_Potential_Mitigations_Description_For_CWE(Potential_Mitigations):
    if Potential_Mitigations is None:
        return []
    if isinstance(Potential_Mitigations, list):
        base = []
        for pm in Potential_Mitigations:
            base += CWE_Match(pm["Description"])
    return Make_CWE_Array(Flatter_Unique_Array(base))

def Scan_Potential_Mitigations_Effectiveness_Notes_For_CWE(Potential_Mitigations):
    if Potential_Mitigations is None:
        return []
    if isinstance(Potential_Mitigations, list):
        base = []
        for pm in Potential_Mitigations:
            base += CWE_Match(pm["Effectiveness_Notes"])
    return Make_CWE_Array(Flatter_Unique_Array(base))

def Scan_Alternate_Terms_For_CWE(Alternate_Terms):
    if Alternate_Terms is None:
        return []
    if isinstance(Alternate_Terms, list):
        base = []
        for at in Alternate_Terms:
            base += CWE_Match(at["Description"])
    return Make_CWE_Array(Flatter_Unique_Array(base))

def Scan_Notes_For_CWE(Notes):
    if Notes is None:
        return []
    if isinstance(Notes, list):
        base = []
        for n in Notes:
            base += CWE_Match(n["Text"])
    return Make_CWE_Array(Flatter_Unique_Array(base))

def Scan_Observed_Examples_For_CWE(Observed_Examples):
    if Observed_Examples is None:
        return []
    if isinstance(Observed_Examples, list):
        base = []
        for oe in Observed_Examples:
            base += CWE_Match(oe["Description"])
    return Make_CWE_Array(Flatter_Unique_Array(base))

def Scan_Demonstrative_Examples_Body_For_CWE(Demonstrative_Example_Body):
    if Demonstrative_Example_Body is None:
        return []
    if isinstance(Demonstrative_Example_Body, list):
        base = []
        for de in Demonstrative_Example_Body:
            base += CWE_Match(de["Body_Text"])
    return Make_CWE_Array(Flatter_Unique_Array(base))

def Scan_Related_Attack_Patterns_For_CAPEC(Related_Attack_Patterns):
    if Related_Attack_Patterns is None:
        return []
    if isinstance(Related_Attack_Patterns, list):
        base = []
        for ra in Related_Attack_Patterns:
            base += ra["CAPEC_ID"]
    return Make_CAPEC_Array(Flatter_Unique_Array(base))

def Scan_Observed_Examples_For_CVE(Observed_Examples):
    if Observed_Examples is None:
        return []
    if isinstance(Observed_Examples, list):
        base = []
        for oe in Observed_Examples:
            base.append(oe["Reference"])
    return Flatter_Unique_Array(base)

def Get_Description(Description):
    if isinstance(Description, str):
        return Description
    elif isinstance(Description, list):
        return "\n".join(Description)
    elif isinstance(Description, dict):
        return Convert_Description_Dict_To_Text(Description)
    return undefined

def Get_Extended_Description(Extended_Description):
    return Get_Description(Extended_Description)

def Get_Related_Weaknesses(Related_Weaknesses):
    Related_Weakness = Related_Weaknesses.get("Related_Weakness", [])
    Related_Weakness = [Related_Weakness] if isinstance(Related_Weakness, dict) else Related_Weakness
    return [
        dict(
            Nature=x.get("@Nature", undefined),
            CWE_ID=x.get("@CWE_ID", undefined),
            View_ID=x.get("@View_ID", undefined),
            Ordinal=x.get("@Ordinal", undefined)
        ) for x in Related_Weakness
    ]

def Get_Alternate_Terms(Alternate_Terms):
    Alternate_Term = Alternate_Terms.get("Alternate_Term", [])
    Alternate_Term = [Alternate_Term] if isinstance(Alternate_Term, dict) else Alternate_Term
    return [
        dict(
            Term=x.get("Term", undefined),
            Description=x.get("Description", undefined)
        ) for x in Alternate_Term
    ]

def Get_Weakness_Ordinalities(Weakness_Ordinalities):
    Weakness_Ordinality = Weakness_Ordinalities.get("Weakness_Ordinality", [])
    if isinstance(Weakness_Ordinality, dict):
        Weakness_Ordinality = [Weakness_Ordinality]
        return [
            dict(
                Ordinality=x.get("Ordinality", undefined),
                Description=x.get("Description", undefined)
            ) for x in Weakness_Ordinality
        ]
    return [dict(Ordinality=undefined, Description=undefined)]

def Get_Applicable_Platforms(Applicable_Platforms):
    Language = []
    Paradigm = {}
    Technology = {}
    if isinstance(Applicable_Platforms, dict):
        lang = Applicable_Platforms.get("Language", [])
        lang = [lang] if isinstance(lang, dict) else lang
        Language = [
            dict(
                Class=x.get("@Class", undefined),
                Name=x.get("@Name", undefined),
                Prevalence=x.get("@Prevalence", undefined)
            ) for x in lang
        ]
        par = Applicable_Platforms.get("Paradigm", {})
        Paradigm = dict(
            Name=par.get("@Name", undefined),
            Prevalence=par.get("@Prevalence", undefined)
        )
        tech = Applicable_Platforms.get("Technology", {})
        tech = [tech] if isinstance(tech, dict) else tech
        Technology = [
            dict(
                Name=x.get("@Name", undefined),
                Prevalence=x.get("@Prevalence", undefined)
            ) for x in tech
        ]
    return dict(
        Language=Language,
        Paradigm=Paradigm,
        Technology=Technology
    )

def Get_Background_Details(Background_Details):
    Background_Detail = Background_Details.get("Background_Detail", "")
    if isinstance(Background_Detail, str):
        return Background_Detail
    elif isinstance(Background_Detail, dict):
        return Convert_Description_Dict_To_Text(Background_Detail)
    return undefined

def Get_Notes(Notes):
    Note = Notes.get("Note", {})
    Note = [Note] if isinstance(Note, dict) else Note
    return [
        dict(
            Type=x.get("@Type", undefined),
            Text=x.get("#text", undefined)
        ) for x in Note
    ]
    
def Get_Related_Attack_Patterns(Related_Attack_Patterns):
    Related_Attack_Pattern = Related_Attack_Patterns.get("Related_Attack_Pattern", [])
    Related_Attack_Pattern = [Related_Attack_Pattern] if isinstance(Related_Attack_Pattern, dict) else Related_Attack_Pattern        
    return [
        dict(
            CAPEC_ID=x.get("@CAPEC_ID", undefined)
        ) for x in Related_Attack_Pattern
    ]

def Get_Demonstrative_Examples_Body(Demonstrative_Examples_Body):
    Demonstrative_Example_Body = Demonstrative_Examples_Body.get("Demonstrative_Example", [])
    Demonstrative_Example_Body = [Demonstrative_Example_Body] if isinstance(Demonstrative_Example_Body, dict) else Demonstrative_Example_Body
    return [
        dict(
            Demonstrative_Example_ID=x.get("@Demonstrative_Example_ID", undefined),
            Intro_Text=x.get("Intro_Text", undefined),
            Body_Text=x.get("Body_Text", undefined)
        ) for x in Demonstrative_Example_Body
    ]

def Get_Observed_Examples(Observed_Examples):
    Observed_Example = Observed_Examples.get("Observed_Example", [])
    Observed_Example = [Observed_Example] if isinstance(Observed_Example, dict) else Observed_Example
    return [
        dict(
            Reference=x.get("Reference", undefined),
            Description=x.get("Description", undefined),
            Link=x.get("Link", undefined)
        ) for x in Observed_Example
    ]

def Get_Content_History(Content_History):
    sub = Content_History.get("Submission", {})
    mod = Content_History.get("Modification", [])
    pen = Content_History.get("Previous_Entry_Name", [])
    mod = [mod] if isinstance(mod, dict) else mod
    pen = [pen] if isinstance(pen, dict) else pen
    Submission = [
        dict(
            Submission_Name=sub.get("Submission_Name", undefined),
            Submission_Organization=sub.get("Submission_Organization", undefined),
            Submission_Date=sub.get("Submission_Date", undefined)
        )
    ]
    Modification = [
        dict(
            Modification_Name=x.get("Modification_Name", undefined),
            Modification_Organization=x.get("Modification_Organization", undefined),
            Modification_Date=x.get("Modification_Date", undefined),
            Modification_Comment=x.get("Modification_Comment", undefined)
        ) for x in mod
    ]
    Previous_Entry_Name = [
        dict(
            Date=x.get("@Date", undefined),
            Text=x.get("#text", undefined)
        ) for x in pen
    ]
    return Submission, Modification, Previous_Entry_Name

def Get_Relationships(Relationships):
    Has_Member = Relationships.get("Has_Member", [])
    Has_Member = [Has_Member] if isinstance(Has_Member, dict) else Has_Member
    return [
        dict(
            CWE_ID=x.get("@CWE_ID", undefined),
            View_ID=x.get("@View_ID", undefined)
        ) for x in Has_Member
    ]

def Get_References(References):
    Reference = References.get("Reference", [])
    Reference = [Reference] if isinstance(Reference, dict) else Reference
    return [
        dict(
            External_Reference_ID=x.get("@External_Reference_ID", undefined),
            Section=x.get("@Section", undefined)
        ) for x in Reference
    ]

def Get_Audience(Audience):
    Stakeholder = Audience.get("Stakeholder", [])
    Stakeholder = [Stakeholder] if isinstance(Stakeholder, dict) else Stakeholder
    return [
        dict(
            Type=x.get("Type", undefined),
            Description=x.get("Description", undefined) #.decode('unicode_escape').encode('ascii','ignore')
        ) for x in Stakeholder
    ]

def Get_Potential_Mitigations(Potential_Mitigations):
    Mitigation = Potential_Mitigations.get("Mitigation", [])
    Mitigation = [Mitigation] if isinstance(Mitigation, dict) else Mitigation
    return [
        dict(
            Mitigation_ID=x.get("@Mitigation_ID", undefined),
            Method=x.get("Method", undefined),
            Phase=Convert_List_Of_Strings_To_One_String(x.get("Phase", undefined)),
            Strategy=x.get("Strategy", undefined),
            Effectiveness=x.get("Effectiveness", undefined),
            Effectiveness_Notes=x.get("Effectiveness_Notes", undefined),
            Description=Convert_Description_Dict_To_Text(x.get("Description", {}))
        ) for x in Mitigation
    ]

# ############################################################################
#  Weaknesses 
# ############################################################################

def Parse_Weakness_Section(Weaknesses_Sections):
    Weaknesses = list()
    for One_Weakness in Weaknesses_Section:
        Weakness = dict()
        Weakness["ID"] = One_Weakness.get("@ID", undefined)
        Weakness["Class"] = "Weakness"
        Weakness["Type"] = undefined
        Weakness["Name"] = One_Weakness.get("@Name", undefined)
        Weakness["Abstraction"] = One_Weakness.get("@Abstraction", undefined)
        Weakness["Structure"] = One_Weakness.get("@Structure", undefined)
        Weakness["Status"] = One_Weakness.get("@Status", undefined)
        Weakness["Description"] = Get_Description(One_Weakness.get("Description", ""))
        Weakness["Extended_Description"] = Get_Extended_Description(One_Weakness.get("Extended_Description", ""))
        Weakness["Related_Weaknesses"] = Get_Related_Weaknesses(One_Weakness.get("Related_Weaknesses", {}))
        Weakness["Weakness_Ordinalities"] = Get_Weakness_Ordinalities(One_Weakness.get("Weakness_Ordinalities", {}))
        Weakness["Applicable_Platforms"] = Get_Applicable_Platforms(One_Weakness.get("Applicable_Platforms", {}))
        Weakness["Background_Details"] = Get_Background_Details(One_Weakness.get("Background_Details", {}))
        Weakness["Notes"] = Get_Notes(One_Weakness.get("Notes", {}))
        Weakness["Related_Attack_Patterns"] = Get_Related_Attack_Patterns(One_Weakness.get("Related_Attack_Patterns", {}))
        Weakness["Demonstrative_Examples_Body"] = Get_Demonstrative_Examples_Body(One_Weakness.get("Demonstrative_Examples", {}))
        Weakness["Observed_Examples"] = Get_Observed_Examples(One_Weakness.get("Observed_Examples", {}))
        Weakness["Alternate_Terms"] = Get_Alternate_Terms(One_Weakness.get("Alternate_Terms", {}))
        Weakness["Content_History_Submission"] = [] # [{}]
        Weakness["Content_History_Modification"] = [] # [{}]
        Weakness["Content_History_Previous_Entry_Name"] = [] # [{}]
        Weakness["Objective"] = undefined
        Weakness["Audience"] = [] # [{}]
        Weakness["Relationships"] = [] # [{}]
        Weakness["References"] = [] #[{}]
        Weakness["Potential_Mitigations"] = Get_Potential_Mitigations(One_Weakness.get("Potential_Mitigations", {}))
        CWE_List_From_Alternate_Terms = Scan_Alternate_Terms_For_CWE(Weakness["Alternate_Terms"])
        CWE_List_From_Demonstrative_Examples_Body = Scan_Demonstrative_Examples_Body_For_CWE(Weakness["Demonstrative_Examples_Body"])
        CWE_List_From_Observed_Examples = Scan_Observed_Examples_For_CWE(Weakness["Observed_Examples"])
        CWE_List_From_Related_Weakness = Scan_Related_Weakness_For_CWE(Weakness["Related_Weaknesses"])
        CWE_List_From_Potential_Mitigations_Description = Scan_Potential_Mitigations_Description_For_CWE(Weakness["Potential_Mitigations"])
        CWE_List_From_Potential_Mitigations_Effectiveness_Notes = Scan_Potential_Mitigations_Effectiveness_Notes_For_CWE(Weakness["Potential_Mitigations"])
        Weakness["CWE_List"] = list()
        Weakness["CWE_List"] = Flatter_Unique_Array(
            CWE_List_From_Alternate_Terms + \
            CWE_List_From_Demonstrative_Examples_Body + \
            CWE_List_From_Observed_Examples + \
            CWE_List_From_Related_Weakness + \
            CWE_List_From_Potential_Mitigations_Description + \
            CWE_List_From_Potential_Mitigations_Effectiveness_Notes
            )
        Weakness["CAPEC_List"] = list()
        Weakness["CAPEC_List"] = Scan_Related_Attack_Patterns_For_CAPEC(Weakness["Related_Attack_Patterns"])
        Weakness["CVE_List"] = list()
        Weakness["CVE_List"] = Scan_Observed_Examples_For_CVE(Weakness["Observed_Examples"])
        Weaknesses.append(Weakness)
    return Weaknesses

# ############################################################################
#  Categories
# ############################################################################


def Parse_Categories_Section(Categories_Section):
    Categories = list()
    for One_Category in Categories_Section:
        Category = dict()
        Category["ID"] = One_Category.get("@ID", undefined)
        Category["Class"] = "Category"
        Category["Type"] = undefined
        Category["Name"] = One_Category.get("@Name", undefined)
        Category["Abstraction"] = undefined
        Category["Structure"] = undefined
        Category["Status"] = One_Category.get("@Status", undefined)
        Category["Description"] = Get_Description(One_Category.get("Summary", ""))
        Category["Extended_Description"] = undefined
        Category["Related_Weaknesses"] = [] # [{}]
        Category["Weakness_Ordinalities"] = [] # [{}]
        Category["Applicable_Platforms"] = {} # {[{}], {}, [{}]}
        Category["Background_Details"] = undefined
        Category["Notes"] = [] # [{}]
        Category["Related_Attack_Patterns"] = [] #[{}]
        Category["Demonstrative_Examples_Body"] = [] # [{}]
        Category["Observed_Examples"] = [] #[{}]
        Category["Alternate_Terms"] = [] # [{}]
        Submission, Modification, Previous_Entry_Name = Get_Content_History(One_Category.get("Content_History", {}))
        Category["Content_History_Submission"] = Submission # [{}]
        Category["Content_History_Modification"] = Modification # [{}]
        Category["Content_History_Previous_Entry_Name"] = Previous_Entry_Name # [{}]
        Category["Objective"] = undefined
        Category["Audience"] = [] # [{}]
        Category["Relationships"] = Get_Relationships(One_Category.get("Relationships", {}))
        Category["Notes"] = [] # [{}]
        Category["References"] = Get_References(One_Category.get("References", {}))
        Category["Potential_Mitigations"] = [] # [{}]
        Category["CWE_List"] = []
        Category["CAPEC_List"] = []
        Category["CVE_List"] = []
        Categories.append(Category)
    return Categories

# ############################################################################
#  Views
# ############################################################################

def Parse_Views_Section(Views_Section):
    Views = list()
    for One_View in Views_Section:
        View = dict()
        View["ID"] = One_View.get("@ID", undefined)
        View["Class"] = "View"
        View["Type"] = One_View.get("@Type", undefined)
        View["Name"] = One_View.get("@Name", undefined)
        View["Abstraction"] = undefined
        View["Structure"] = undefined
        View["Status"] = One_View.get("@Status", undefined)
        View["Description"] = undefined
        View["Extended_Description"] = undefined
        View["Related_Weaknesses"] = [] # [{}]
        View["Weakness_Ordinalities"] = [] # [{}]
        View["Applicable_Platforms"] = {} # {[{}], {}, [{}]}
        View["Background_Details"] = undefined
        View["Notes"] = [] # [{}]
        View["Related_Attack_Patterns"] = [] #[{}]
        View["Demonstrative_Examples_Body"] = [] # [{}]
        View["Observed_Examples"] = [] #[{}]
        View["Alternate_Terms"] = [] # [{}]
        Submission, Modification, Previous_Entry_Name = Get_Content_History(One_View.get("Content_History", {}))
        View["Content_History_Submission"] = Submission # [{}]
        View["Content_History_Modification"] = Modification # [{}]
        View["Content_History_Previous_Entry_Name"] = Previous_Entry_Name # [{}]
        View["Objective"] = One_View.get("Objective", undefined)
        View["Audience"] = Get_Audience(One_View.get("Audience", {}))
        View["Relationships"] = Get_Relationships(One_View.get("Members", {}))
        View["Notes"] = Get_Notes(One_View.get("Notes", {}))  
        View["References"] = [] #[{}]      
        View["Potential_Mitigations"] = [] # [{}]
        View["CWE_List"] = Scan_Notes_For_CWE(View["Notes"])
        View["CAPEC_List"] = []
        View["CVE_List"] = []
        Views.append(View)
    return Views

# ############################################################################
#  Views
# ############################################################################

def Parse_External_References(External_References_Section):
    External_References = list()
    for One_External_Reference in External_References_Section:
        External_Reference = ddict()
        External_Reference.Reference_ID = One_External_Reference.get("@Reference_ID", undefined)
        External_Reference.Author = []
        Author = One_External_Reference.get("Author", [])
        Author = [Author] if isinstance(Author, str) else Author
        External_Reference.Author = [x for x in Author]
        External_Reference.Title = One_External_Reference.get("Title", undefined)
        External_Reference.Publication_Year = One_External_Reference.get("Publication_Year", undefined)
        External_Reference.Publication_Month = One_External_Reference.get("Publication_Month", undefined)
        External_Reference.Publication_Day = One_External_Reference.get("Publication_Day", undefined)
        External_Reference.URL = One_External_Reference.get("URL", undefined)
        External_References.append(External_Reference)
    return External_References


def Get_All_CWEs_From_Database_File():
    W = Parse_Weakness_Section(Weaknesses_Section)
    print("[+] Get {} Weaknesses".format(len(W)))
    C = Parse_Categories_Section(Categories_Section)
    print("[+] Get {} Categories".format(len(C)))
    V = Parse_Views_Section(Views_Section)
    print("[+] Get {} Views".format(len(V)))
    R = W + C + V
    print("[+] Complete with {} result elements".format(len(R)))
    return R    


class CWE(peewee.Model):
    class Meta:
        database = database
        ordering = ("cwe_id")
        table_name = "cwe"

    id = peewee.PrimaryKeyField(null=False)
    cwe_id = peewee.TextField(default="")
    cwe_class = peewee.TextField(default="")
    cwe_type = peewee.TextField(default="")
    name = peewee.TextField(default="")
    abstraction = peewee.TextField(default="")
    structure = peewee.TextField(default="")
    status = peewee.TextField(default="")
    description = peewee.TextField(default="")
    extended_description = peewee.TextField(default="")
    related_weakness = ArrayField(peewee.TextField, default=[])
    weakness_ordinalities = ArrayField(peewee.TextField, default=[])
    applicable_platforms = JSONField(default={})
    background_details = peewee.TextField(default="")
    notes = peewee.TextField(default="")
    related_attack_patterns = ArrayField(peewee.TextField, default=[])
    demonstrative_examples_body = ArrayField(peewee.TextField, default=[])
    observed_examples = ArrayField(peewee.TextField, default=[])
    alternate_terms = ArrayField(peewee.TextField, default=[])
    content_history_submission = ArrayField(peewee.TextField, default=[])
    content_history_modification = ArrayField(peewee.TextField, default=[])
    content_history_previous_entry_name = ArrayField(peewee.TextField, default=[])
    objective = peewee.TextField(default="")
    audience = ArrayField(peewee.TextField, default=[])
    relationships = ArrayField(peewee.TextField, default=[])
    references = ArrayField(peewee.TextField, default=[])
    potential_mitigations = ArrayField(peewee.TextField, default=[])
    cwe_list = ArrayField(peewee.TextField, default=[])
    cve_list = ArrayField(peewee.TextField, default=[])
    capec_list = ArrayField(peewee.TextField, default=[])

    def __unicode__(self):
            return "cwe"

    def __str__(self):
        return str(self.cwe_id)

    def save(self, **kwargs):
        with database.transaction():
            self.related_weakness = [json.dumps(x) for x in self.related_weakness]
            self.weakness_ordinalities = [json.dumps(x) for x in self.weakness_ordinalities]
            self.related_attack_patterns = [json.dumps(x) for x in self.related_attack_patterns]
            self.demonstrative_examples_body = [json.dumps(x) for x in self.demonstrative_examples_body]
            self.observed_examples = [json.dumps(x) for x in self.observed_examples]
            self.alternate_terms = [json.dumps(x) for x in self.alternate_terms]
            self.content_history_submission = [json.dumps(x) for x in self.content_history_submission]
            self.content_history_modification = [json.dumps(x) for x in self.content_history_modification]
            self.content_history_previous_entry_name = [json.dumps(x) for x in self.content_history_previous_entry_name]
            self.audience = [json.dumps(x) for x in self.audience]
            self.relationships = [json.dumps(x) for x in self.relationships]
            self.references = [json.dumps(x) for x in self.references]
            self.potential_mitigations = [json.dumps(x) for x in self.potential_mitigations]
            peewee.Model.save(self, **kwargs)

    @property
    def to_json(self):
        return dict(
            id=self.id,
            cwe_id=self.cwe_id,
            cwe_class=self.cwe_class,
            cwe_type=self.cwe_type,
            name=self.name,
            abstraction=self.abstraction,
            structure=self.structure,
            status=self.status,
            description=self.description,
            extended_description=self.extended_description,
            related_weakness=[json.loads(x) for x in self.related_weakness],
            weakness_ordinalities=[json.loads(x) for x in self.weakness_ordinalities],
            applicable_platforms=self.applicable_platforms,
            background_details=self.background_details,
            notes=self.notes,
            related_attack_patterns=[json.loads(x) for x in self.related_attack_patterns],
            demonstrative_examples_body=[json.loads(x) for x in self.demonstrative_examples_body],
            observed_examples=[json.loads(x) for x in self.observed_examples],
            alternate_terms=[json.loads(x) for x in self.alternate_terms],
            content_history_submission=[json.loads(x) for x in self.content_history_submission],
            content_history_modification=[json.loads(x) for x in self.content_history_modification],
            content_history_previous_entry_name=[json.loads(x) for x in self.content_history_previous_entry_name],
            objective=self.objective,
            audience=[json.loads(x) for x in self.audience],
            relationships=[json.loads(x) for x in self.relationships],
            references=[json.loads(x) for x in self.references],
            potential_mitigations=[json.loads(x) for x in self.potential_mitigations],
            cwe_list=self.cwe_list,
            cve_list=self.cve_list,
            capec_list=self.capec_list
        )

def Create_Or_Update_One_CWE_Vulner_In_Postgres(One_Vulner):
    ID = -1
    CWE_From_PG = CWE.get_or_none(CWE.cwe_id == One_Vulner["ID"])
    if CWE_From_PG is None:
        New_CWE = CWE(
            cwe_id=One_Vulner["ID"],
            cwe_class=One_Vulner["Class"],
            cwe_type=One_Vulner["Type"],
            name=One_Vulner["Name"],
            abstraction=One_Vulner["Abstraction"],
            structure=One_Vulner["Structure"],
            status=One_Vulner["Status"],
            description=One_Vulner["Description"],
            extended_description=One_Vulner["Extended_Description"],
            related_weakness=One_Vulner["Related_Weaknesses"],
            weakness_ordinalities=One_Vulner["Weakness_Ordinalities"],
            applicable_platforms=One_Vulner["Applicable_Platforms"],
            background_details=One_Vulner["Background_Details"],
            notes=One_Vulner["Notes"],
            related_attack_patterns=One_Vulner["Related_Attack_Patterns"],
            demonstrative_examples_body=One_Vulner["Demonstrative_Examples_Body"],
            observed_examples=One_Vulner["Observed_Examples"],
            alternate_terms=One_Vulner["Alternate_Terms"],
            content_history_submission=One_Vulner["Content_History_Submission"],
            content_history_modification=One_Vulner["Content_History_Modification"],
            content_history_previous_entry_name=One_Vulner["Content_History_Previous_Entry_Name"],
            objective=One_Vulner["Objective"],
            audience=One_Vulner["Audience"],
            relationships=One_Vulner["Relationships"],
            references=One_Vulner["References"],
            potential_mitigations=One_Vulner["Potential_Mitigations"],
            cwe_list=One_Vulner["CWE_List"],
            cve_list=One_Vulner["CVE_List"],
            capec_list=One_Vulner["CAPEC_List"]
        )
        New_CWE.save()
    return ID

def Pretty_Print_Json(Json_To_Print):
    Json_Keys = Json_To_Print.keys()
    for One_Key in Json_Keys:
        print("{}: {}\n".format(One_Key, Json_To_Print[One_Key]))

def run():
    if database.is_closed:
        database.connect()
    CWE.drop_table()
    CWE.create_table()

    CWE_Vulnerabilities = Get_All_CWEs_From_Database_File()

    CWE_Vulnerabilities_IDs = list(
        map(Create_Or_Update_One_CWE_Vulner_In_Postgres, CWE_Vulnerabilities)
    )

    print("Create {} records in pistgres".format(len(CWE_Vulnerabilities_IDs)))

    if not database.is_closed:
        database.close()

def main():
    run()


if __name__ == "__main__":
    main()