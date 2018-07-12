import xmltodict
import json

undefined = "undefined"

with open('cwe.xml', 'r') as fp:
    xml = fp.read()

jj = xmltodict.parse(xml)

o = jj.get("Weakness_Catalog", {})

# Views

views = o.get("Views", {})
view = views.get("View", [])

print("view count: {}".format(len(view)))

parsed_views = []

for v in view:
    template = {}
    template["id"] = v.get("@ID", undefined)
    template["name"] = v.get("@Name", undefined)
    template["status"] = v.get("@Status", undefined)
    # View_Structure
    template["view_structure"] = v.get("View_Structure", undefined)
    # View_Objective
    template["view_objective"] = ""
    text = v.get("View_Objective", {}).get("Text", [])
    for t in text:
        template["view_objective"] += t
    if template["view_objective"] == "":
        template["view_objective"] = undefined
    # View_Audience
    template["view_audience"] = ""
    text = v.get("View_Audience", {}).get("Audience", [])
    if isinstance(text, dict):
        text = [text]
    for t in text:
        _1 = t.get("Stakeholder", "")
        _2 = t.get("Stakeholder_Description", {})
        _3 = _2.get("Text", "")
        template["view_audience"] += _1 + "\n" + _3
    if template["view_audience"] == "":
        template["view_audience"] = undefined
    # Relationships
    template["relationships"] = []
    rel = v.get("Relationships", {}).get("Relationship", [])
    for r in rel:
        tmpl = {}
        tmpl["relationship_views_id_ordinal"] = r.get("Relationship_Views", {}).get("Relationship_View_ID", {}).get("@Ordinal", undefined)
        tmpl["relationship_views_id_text"] = r.get("Relationship_Views", {}).get("Relationship_View_ID", {}).get("#text", undefined)
        tmpl["relationship_target_form"] = r.get("Relationship_Target_Form", undefined)
        tmpl["relationship_nature"] = r.get("Relationship_Nature", undefined)
        tmpl["relationship_target_id"] = r.get("Relationship_Target_ID", undefined)
        template["relationships"].append(tmpl)
    # Content_History
    template["content_history_modification"] = []
    mod = v.get("Content_History", {}).get("Modification", [])
    if isinstance(mod, dict):
        mod = [mod]
    for m in mod:
        tmpl = {}
        tmpl["modification_source"] = m.get("@Modification_Source", undefined)
        tmpl["modifier"] = m.get("Modifier", undefined)
        tmpl["modifier_organization"] = m.get("Modifier_Organization", undefined)
        tmpl["modification_date"] = m.get("Modification_Date", undefined)
        tmpl["modification_comment"] = m.get("Modification_Comment", undefined)
        template["content_history_modification"].append(tmpl)
    template["previous_entry_name_change_date"] = v.get("Previous_Entry_Names", {}).get("Previous_Entry_Name", {}).get("@Name_Change_Date", undefined)
    template["previous_entry_name_change_text"] = v.get("Previous_Entry_Names", {}).get("Previous_Entry_Name", {}).get("#text", undefined)

    if template["id"] != undefined:
        parsed_views.append(template)

# Categories

categories = o.get("Categories", {})
categorie = categories.get("Category", [])

parsed_categories = []

for cat in categorie:
    template = {}
    template["id"] = cat.get("@ID", undefined)
    template["name"] = cat.get("@Name", undefined)
    template["status"] = cat.get("@Status", undefined)
    template["description"] = cat.get("Description", {}).get("Description_Summary", undefined)
    # Content_History
    ch = cat.get("Content_History", {})
    mod = ch.get("Modification", [])
    # Content_History -> Modifications
    template["content_history_modifications"] = []
    if isinstance(mod, dict):
        mod = [mod]
    for m in mod:
        tmpl = {}
        tmpl["modification_source"] = m.get("@Modification_Source", undefined)
        tmpl["modifier_organization"] = m.get("Modifier_Organization", undefined)
        tmpl["modification_date"] = m.get("Modification_Date", undefined)
        tmpl["modification_comment"] = m.get("Modification_Comment", undefined)
        template["content_history_modifications"].append(tmpl)
    # Taxonomy_Mappings
    template["taxonomy_mapping"] = []
    tm = cat.get("Taxonomy_Mappings", {}).get("Taxonomy_Mapping", [])
    if isinstance(tm, dict):
        tm = [tm]
    for t in tm:
        tmpl = {}
        tmpl["mapped_taxonomy_name"] = t.get("@Mapped_Taxonomy_Name", undefined)
        tmpl["mapped_node_name"] = t.get("Mapped_Node_Name", undefined)
        tmpl["mapped_node_id"] = t.get("Mapped_Node_ID", undefined)
        template["taxonomy_mapping"].append(tmpl)
    # Detection_Methods
    template["detection_methods"] = []
    dms = cat.get("Detection_Methods", {})
    dm = dms.get("Detection_Method", [])
    if isinstance(dm, dict):
        dm = [dm]
    for d in dm:
        tmpl = {}
        tmpl["method_name"] = d.get("Method_Name", undefined)
        dscr = d.get("Method_Description", {})
        tmpl["method_description"] = ""
        text = dscr.get("Text", [])
        if isinstance(text, str):
            text = [text]
        for t in text:
            tmpl["method_description"] += t + "\n\n"
        block = dscr.get("Block", [])
        if isinstance(block, dict):
            block = [block]
        for b in block:
            # TODO: Check block nature

            # TODO: view line 6316
            
            block_nature = b.get("@Block_Nature", "")
            block_text = b.get("Text", [])
            bt = ""
            if isinstance(block_text, str):
                block_text = [block_text]
            for blt in block_text:
                if block_nature == "List":
                    tmpl["method_description"] += "- " + blt.replace('\t', '') + "\n"
                else:
                    tmpl["method_description"] += blt.replace('\t', "") + "\n"

        tmpl["method_effectiveness"] = d.get("Method_Effectiveness", undefined)
        template["detection_methods"].append(tmpl)
    # Relationships
    template["relationships"] = []
    rel = cat.get("Relationships", {}).get("Relationship", [])
    if isinstance(rel, dict):
        rel = [rel]
    for r in rel:
        tmpl = {}
        Relationship_Views = r.get("Relationship_Views", {})
        Relationship_View_ID = Relationship_Views.get("Relationship_View_ID", {})
        if isinstance(Relationship_View_ID, str):
            tmpl["relationship_views_id_ordinal"] = Relationship_View_ID
        elif isinstance(Relationship_View_ID, dict):
            tmpl["relationship_views_id_ordinal"] = Relationship_View_ID.get("@Ordinal", undefined)
            tmpl["relationship_views_id_text"] = Relationship_View_ID.get("#text", undefined)
        else:
            tmpl["relationship_views_id_ordinal"] = undefined
            tmpl["relationship_views_id_text"] = undefined
        tmpl["relationship_target_form"] = r.get("Relationship_Target_Form", undefined)
        tmpl["relationship_nature"] = r.get("Relationship_Nature", undefined)
        tmpl["relationship_target_id"] = r.get("Relationship_Target_ID", undefined)
        template["relationships"].append(tmpl)

    if template["id"] != undefined:
        parsed_categories.append(template)

for pc in parsed_categories:
    if pc["id"] == "16":
        print("id:\n{}".format(pc["id"]))
        print("name:\n{}".format(pc["name"]))
        print("status:\n{}".format(pc["status"]))
        print("description:\n{}".format(pc["description"]))
        print("content_history_modifications:\n{}".format(pc["content_history_modifications"]))
        print("taxonomy_mapping:\n{}".format(pc["taxonomy_mapping"]))
        print("detection_methods:\n{}".format(pc["detection_methods"]))
        print("relationships:\n{}".format(pc["relationships"]))

# # Weaknesses
#
# weaknesses = o.get("Weaknesses", {})
# weakness = weaknesses.get("Weakness", [])
#
# # Compound_Elements
#
# compaund_elements = o.get("Compaund_Elements", {})
# compaund_element = compaund_elements.get("Compound_Element", [])
