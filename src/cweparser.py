# -*- coding: utf-8 -*-

import re
import xmltodict
import json
from dotted_dict import DottedDict as ddict

import sys
reload(sys)
sys.setdefaultencoding('utf8')

from example import database

undefined = "undefined"


DEBUG = False

def write_xmpl_to_json_file():
    with open('./src/cwe.xml', 'r') as fp:
        xml = fp.read()
        j = xmltodict.parse(xml)
        with open('./src/cwec.json', 'w') as fp:
            json.dump(j, fp)

def load_json_from_file():
    with open('./src/cwec.json', 'r') as fp:
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

def Convert_Description_Dict_To_Text(dictionary):
    text = ""
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
                

    return text

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
            Description=x.get("Description", undefined).decode('unicode_escape').encode('ascii','ignore')
        ) for x in Stakeholder
    ]

# ############################################################################
#  Weaknesses 
# ############################################################################

def Parse_Weakness_Section(Weaknesses_Sections):
    Weaknesses = list()
    for One_Weakness in Weaknesses_Section:
        Weakness = ddict()
        Weakness.ID = One_Weakness.get("@ID", undefined)
        Weakness.Class = "Weakness"
        Weakness.Type = undefined
        Weakness.Name = One_Weakness.get("@Name", undefined)
        Weakness.Abstraction = One_Weakness.get("@Abstraction", undefined)
        Weakness.Structure = One_Weakness.get("@Structure", undefined)
        Weakness.Status = One_Weakness.get("@Status", undefined)
        Weakness.Description = Get_Description(One_Weakness.get("Description", ""))
        Weakness.Extended_Description = Get_Extended_Description(One_Weakness.get("Extended_Description", ""))
        Weakness.Related_Weaknesses = Get_Related_Weaknesses(One_Weakness.get("Related_Weaknesses", {}))
        Weakness.Weakness_Ordinalities = Get_Weakness_Ordinalities(One_Weakness.get("Weakness_Ordinalities", {}))
        Weakness.Applicable_Platforms = Get_Applicable_Platforms(One_Weakness.get("Applicable_Platforms", {}))
        Weakness.Background_Details = Get_Background_Details(One_Weakness.get("Background_Details", {}))
        Weakness.Notes = Get_Notes(One_Weakness.get("Notes", {}))
        Weakness.Related_Attack_Patterns = Get_Related_Attack_Patterns(One_Weakness.get("Related_Attack_Patterns", {}))
        Weakness.Observed_Examples = Get_Observed_Examples(One_Weakness.get("Observed_Examples", {}))
        Weakness.Content_History_Submission = [] # [{}]
        Weakness.Content_History_Modification = [] # [{}]
        Weakness.Content_History_Previous_Entry_Name = [] # [{}]
        Weakness.Objective = undefined
        Weakness.Audience = [] # [{}]
        Weakness.Relationships = [] # [{}]
        Weakness.Notes = [] # [{}]
        Weakness.References = [] #[{}]
        Weaknesses.append(Weakness)
    return Weaknesses

# ############################################################################
#  Categories
# ############################################################################


def Parse_Categories_Section(Categories_Section):
    Categories = list()
    for One_Category in Categories_Section:
        Category = ddict()
        Category.ID = One_Category.get("@ID", undefined)
        Category.Class = "Category"
        Category.Type = undefined
        Category.Name = One_Category.get("@Name", undefined)
        Category.Abstraction = undefined
        Category.Structure = undefined
        Category.Status = One_Category.get("@Status", undefined)
        Category.Description = Get_Description(One_Category.get("Summary", ""))
        Category.Extended_Description = undefined
        Category.Related_Weaknesses = [] # [{}]
        Category.Weakness_Ordinalities = [] # [{}]
        Category.Applicable_Platforms = {} # {[{}], {}, [{}]}
        Category.Background_Details = undefined
        Category.Notes = [] # [{}]
        Category.Related_Attack_Patterns = [] #[{}]
        Category.Observed_Examples = [] #[{}]
        Submission, Modification, Previous_Entry_Name = Get_Content_History(One_Category.get("Content_History", {}))
        Category.Content_History_Submission = Submission # [{}]
        Category.Content_History_Modification = Modification # [{}]
        Category.Content_History_Previous_Entry_Name = Previous_Entry_Name # [{}]
        Category.Objective = undefined
        Category.Audience = [] # [{}]
        Category.Relationships = Get_Relationships(One_Category.get("Relationships", {}))
        Category.Notes = [] # [{}]
        Category.References = Get_References(One_Category.get("References", {}))
        Categories.append(Category)
    return Categories

# ############################################################################
#  Views
# ############################################################################

def Parse_Views_Section(Views_Section):
    Views = list()
    for One_View in Views_Section:
        View = ddict()
        View.ID = One_View.get("@ID", undefined)
        View.Class = "View"
        View.Type = One_View.get("@Type", undefined)
        View.Name = One_View.get("@Name", undefined)
        View.Abstraction = undefined
        View.Structure = undefined
        View.Status = One_View.get("@Status", undefined)
        View.Description = undefined
        View.Extended_Description = undefined
        View.Related_Weaknesses = [] # [{}]
        View.Weakness_Ordinalities = [] # [{}]
        View.Applicable_Platforms = {} # {[{}], {}, [{}]}
        View.Background_Details = undefined
        View.Notes = [] # [{}]
        View.Related_Attack_Patterns = [] #[{}]
        View.Observed_Examples = [] #[{}]
        Submission, Modification, Previous_Entry_Name = Get_Content_History(One_View.get("Content_History", {}))
        View.Content_History_Submission = Submission # [{}]
        View.Content_History_Modification = Modification # [{}]
        View.Content_History_Previous_Entry_Name = Previous_Entry_Name # [{}]
        View.Objective = One_View.get("Objective", undefined)
        View.Audience = Get_Audience(One_View.get("Audience", {}))
        View.Relationships = Get_Relationships(One_View.get("Members", {}))
        View.Notes = Get_Notes(One_View.get("Notes", {}))  
        View.References = [] #[{}]      
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


W = Parse_Weakness_Section(Weaknesses_Section)
print("Get {} Weaknesses".format(len(W)))
C = Parse_Categories_Section(Categories_Section)
print("Get {} Categories".format(len(C)))
V = Parse_Views_Section(Views_Section)
print("Get {} Views".format(len(V)))
print("complete")

# TODO: Append related CWEs