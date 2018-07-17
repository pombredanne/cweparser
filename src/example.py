# -*- coding: utf-8 -*-

sections = [
    "Weaknesses",
    "Categories",
    "Views",
    "External_References"
]

members = [
    # Weakness
    "ID",                       # str
    "Class",                    # str
    "Name",                     # str
    "Abstraction",              # str
    "Structure",                # str
    "Status",                   # str
    "Description",              # str
    "Extended_Description",     # str
    "Related_Weaknesses",       # [{}, ]
    "Weakness_Ordinalities",    # [{}, ]
    "Applicable_Platforms",     # {[{}], {}, [{}]}
    "Background_Details",       # str
    "Notes",                    # [{}]
    "Related_Attack_Patterns",  # [{}]
    "Observed_Examples",        # [{}]
    # Categories
    "ID",                       # str
    "Class",                    # str
    "Type",                     # str
    "Name",                     # str
    "Status",                   # str
    "Description",              # str
    "Content_History",          # {Submission={}, Modification=[{}], Previous_Entry_Name=[{}]}
    "Relationships",            # [{}]
    "References",               # [{}]

    # Views
    "ID",                       # str
    "Class",                    # str
    "Name",                     # str
    "Type",                     # str
    "Status",                   # str
    "Objective",                # str
    "Audience",                 # [{}]
    "Members",                  # [{}]
    "Notes",                    # [{}]
    "Content_History",          # {Submission={}, Modification=[{}], Previous_Entry_Name=[{}]}

    # External_References
]

database = {
    "Weakness_Catalog": {
        "@xmlns": "http://cwe.mitre.org/cwe-6",
        "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "@xmlns:xhtml": "http://www.w3.org/1999/xhtml",
        "@Name": "CWE",
        "@Version": "3.1",
        "@Date": "2018-03-29",
        "@xsi:schemaLocation": "http://cwe.mitre.org/cwe-6 http://cwe.mitre.org/data/xsd/cwe_schema_v6.0.1.xsd",
        "Weaknesses": {
            "Weakness": [
                {
                    "@ID": "1004",
                    "@Name": "Sensitive Cookie Without 'HttpOnly' Flag",
                    "@Abstraction": "Variant",
                    "@Structure": "Simple",
                    "@Status": "Incomplete",
                    "Description": "The software uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.",
                    "Extended_Description": {
                        "xhtml:p": [
                            "This could allow attackers to execute unexpected, dangerous commands .",
                            "There are at least two subtypes of OS command injection:",
                            "From a weakness standpoint, these variants represent distinct programmer errors."
                        ],
                        "xhtml:div": {
                            "@style": "margin-left:10px;",
                            "xhtml:ol": {
                                "xhtml:li": [
                                    "The application intends to execute a single, fixed program that is under its own control. ",
                                    "The application accepts an input that it uses to fully select which program to run."
                                ]
                            }
                        }
                    },
                    "Related_Weaknesses": {
                        "Related_Weakness": [
                            {
                                "@Nature": "ChildOf",
                                "@CWE_ID": "287",
                                "@View_ID": "1000",
                                "@Ordinal": "Primary"
                            },
                            {
                                "@Nature": "ChildOf",
                                "@CWE_ID": "287",
                                "@View_ID": "699",
                                "@Ordinal": "Primary"
                            }
                        ]
                    },
                    "Weakness_Ordinalities": {
                        "Weakness_Ordinality": {
                            "Ordinality": "Primary",
                            "Description": "This weakness does not depend on other weaknesses and is the result of choices made during optimization."
                        }
                    },
                    "Applicable_Platforms": {
                        "Language": [
                            {
                                "@Name": "JavaScript",
                                "@Prevalence": "Undetermined"
                            },
                            {
                                "@Name": "PHP",
                                "@Prevalence": "Undetermined"
                            },
                            {
                                "@Class": "Language-Independent",
                                "@Prevalence": "Undetermined"
                            }
                        ],
                        "Paradigm": {
                            "@Name": "Web Based",
                            "@Prevalence": "Undetermined"
                        },
                        "Technology": {
                            "@Name": "Web Server",
                            "@Prevalence": "Undetermined"
                        }
                    },
                    "Background_Details": {
                        "Background_Detail": {
                            "xhtml:p": [
                                "Cryptographic algorithms are the methods by which data is scrambled. There are a small number of well-understood and heavily studied algorithms that should be used by most applications. It is quite difficult to produce a secure algorithm, and even high profile algorithms by accomplished cryptographic experts have been broken.",
                                "Since the state of cryptography advances so rapidly, it is common for an algorithm to be considered \"unsafe\" even if it was once thought to be strong. This can happen when new attacks against the algorithm are discovered, or if computing power increases so much that the cryptographic algorithm no longer provides the amount of protection that was originally thought."
                            ]
                        }
                    },
                    "Notes": {
                        "Note": [
                            {
                                "@Type": "Relationship",
                                "#text": "\"origin validation\" could fall under this."
                            },
                            {
                                "@Type": "Maintenance",
                                "#text": "The specific ways in which the origin is not properly identified should be laid out as separate weaknesses. In some sense, this is more like a category."
                            }
                        ]
                    },
                    "Related_Attack_Patterns": {
                        "Related_Attack_Pattern": [
                            {
                                "@CAPEC_ID": "111"
                            },
                            {
                                "@CAPEC_ID": "141"
                            },
                            {
                                "@CAPEC_ID": "142"
                            },
                            {
                                "@CAPEC_ID": "148"
                            },
                            {
                                "@CAPEC_ID": "218"
                            },
                            {
                                "@CAPEC_ID": "384"
                            },
                            {
                                "@CAPEC_ID": "385"
                            },
                            {
                                "@CAPEC_ID": "386"
                            },
                            {
                                "@CAPEC_ID": "387"
                            },
                            {
                                "@CAPEC_ID": "388"
                            },
                            {
                                "@CAPEC_ID": "389"
                            },
                            {
                                "@CAPEC_ID": "4"
                            }
                        ]
                    },
                    "Observed_Examples": {
                        "Observed_Example": [
                            {
                                "Reference": "CVE-2009-2550",
                                "Description": "Classic stack-based buffer overflow in media player using a long entry in a playlist",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2550"
                            },
                            {
                                "Reference": "CVE-2009-2403",
                                "Description": "Heap-based buffer overflow in media player using a long entry in a playlist",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2403"
                            },
                            {
                                "Reference": "CVE-2009-0689",
                                "Description": "large precision value in a format string triggers overflow",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0689"
                            },
                            {
                                "Reference": "CVE-2009-0690",
                                "Description": "negative offset value leads to out-of-bounds read",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0690"
                            },
                            {
                                "Reference": "CVE-2009-1532",
                                "Description": "malformed inputs cause accesses of uninitialized or previously-deleted objects, leading to memory corruption",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1532"
                            },
                            {
                                "Reference": "CVE-2009-1528",
                                "Description": "chain: lack of synchronization leads to memory corruption",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1528"
                            },
                            {
                                "Reference": "CVE-2009-0558",
                                "Description": "attacker-controlled array index leads to code execution",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0558"
                            },
                            {
                                "Reference": "CVE-2009-0269",
                                "Description": "chain: -1 value from a function call was intended to indicate an error, but is used as an array index instead.",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0269"
                            },
                            {
                                "Reference": "CVE-2009-0566",
                                "Description": "chain: incorrect calculations lead to incorrect pointer dereference and memory corruption",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0566"
                            },
                            {
                                "Reference": "CVE-2009-1350",
                                "Description": "product accepts crafted messages that lead to a dereference of an arbitrary pointer",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1350"
                            },
                            {
                                "Reference": "CVE-2009-0191",
                                "Description": "chain: malformed input causes dereference of uninitialized memory",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0191"
                            },
                            {
                                "Reference": "CVE-2008-4113",
                                "Description": "OS kernel trusts userland-supplied length value, allowing reading of sensitive information",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4113"
                            },
                            {
                                "Reference": "CVE-2003-0542",
                                "Description": "buffer overflow involving a regular expression with a large number of captures",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0542"
                            },
                            {
                                "Reference": "CVE-2017-1000121",
                                "Description": "chain: unchecked message size metadata allows integer overflow (CWE-190) leading to buffer overflow (CWE-119).",
                                "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000121"
                            }
                        ]
                    },
                }
            ]
        },
        "Categories": { # 170567
            "Category": [
                {
                    "@ID": "1",
                    "@Name": "DEPRECATED: Location",
                    "@Status": "Deprecated",
                    "Summary": "This category has been deprecated. It was originally used for organizing the Development View (CWE-699), but it introduced unnecessary complexity and depth to the resulting tree.",
                    "Content_History": {
                        "Submission": {
                            "Submission_Name": "CWE Content Team",
                            "Submission_Organization": "MITRE",
                            "Submission_Date": "2014-07-29"
                        },
                        "Modification": [
                            {
                                "Modification_Name": "CWE Content Team",
                                "Modification_Organization": "MITRE",
                                "Modification_Date": "2008-09-08",
                                "Modification_Comment": "updated Relationships"
                            },
                            {
                                "Modification_Name": "CWE Content Team",
                                "Modification_Organization": "MITRE",
                                "Modification_Date": "2017-01-19",
                                "Modification_Comment": "updated Maintenance_Notes, Relationships"
                            }
                        ],
                        "Previous_Entry_Name": [
                            {
                                "@Date": "2008-04-11",
                                "#text": "HTTP Response Splitting"
                            },
                            {
                                "@Date": "2009-05-27",
                                "#text": "Failure to Sanitize CRLF Sequences in HTTP Headers (aka 'HTTP Response Splitting')"
                            },
                            {
                                "@Date": "2010-06-21",
                                "#text": "Failure to Sanitize CRLF Sequences in HTTP Headers ('HTTP Response Splitting')"
                            }
                        ]
                    },
                    "Relationships": {
                        "Has_Member": [
                            {
                                "@CWE_ID": "111",
                                "@View_ID": "888"
                            },
                            {
                                "@CWE_ID": "227",
                                "@View_ID": "888"
                            },
                            {
                                "@CWE_ID": "242",
                                "@View_ID": "888"
                            },
                        ]
                    },
                    "References": {
                        "Reference": [
                            {
                                "@External_Reference_ID": "REF-9"
                            },
                            {
                                "@External_Reference_ID": "REF-10",
                                "@Section": "pages 69 - 78"
                            }
                        ]
                    },
                    # "References": {
                    #     "Reference": [
                    #         {
                    #             "@External_Reference_ID": "REF-9"
                    #         },
                    #         {
                    #             "@External_Reference_ID": "REF-10",
                    #             "@Section": "pages 69 - 78"
                    #         }
                    #     ]
                    # },
                },
            ]
        },
        "Views": {
            "View": [
                {
                    "@ID": "1000",
                    "@Name": "Research Concepts",
                    "@Type": "Graph",
                    "@Status": "Draft",
                    "Objective": "This view is intended to facilitate research into weaknesses, including their inter-dependencies, and can be leveraged to systematically identify theoretical gaps within CWE. It classifies weaknesses in a way that largely ignores how they can be detected, where they appear in code, and when they are introduced in the software development life cycle. Instead, it is mainly organized according to abstractions of software behaviors.",
                    "Audience": {
                        "Stakeholder": [
                            {
                                "Type": "Academic Researchers",
                                "Description": "Academic researchers can use the high-level classes that lack a significant number of children to identify potential areas for future research."
                            },
                            {
                                "Type": "Vulnerability Analysts",
                                "Description": "Those who perform vulnerability discovery/analysis use this view to identify related weaknesses that might be leveraged by following relationships between higher-level classes and bases."
                            },
                            {
                                "Type": "Assessment Vendors",
                                "Description": "Assessment vendors often use this view to help identify additional weaknesses that a tool may be able to detect as the relationships are more aligned with a tool’s technical capabilities."
                            }
                        ]
                    },
                    "Members": {
                        "Has_Member": [
                            {
                                "@CWE_ID": "682",
                                "@View_ID": "1000"
                            },
                            {
                                "@CWE_ID": "118",
                                "@View_ID": "1000"
                            },
                            {
                                "@CWE_ID": "330",
                                "@View_ID": "1000"
                            },
                        ]
                    },
                    "Notes": {
                        "Note": {
                            "@Type": "Other",
                            "#text": "This view uses a deep hierarchical organization, with more levels of abstraction than other classification schemes. The top-level entries are called Pillars. Where possible, this view uses abstractions that do not consider particular languages, frameworks, technologies, life cycle development phases, frequency of occurrence, or types of resources. It explicitly identifies relationships that form chains and composites, which have not been a formal part of past classification efforts. Chains and composites might help explain why mutual exclusivity is difficult to achieve within security error taxonomies. This view is roughly aligned with MITRE's research into vulnerability theory, especially with respect to behaviors and resources. Ideally, this view will only cover weakness-to-weakness relationships, with minimal overlap and zero categories."
                        }
                    },
                    "Content_History": {
                        "Modification": [
                            {
                                "Modification_Name": "CWE Content Team",
                                "Modification_Organization": "MITRE",
                                "Modification_Date": "2008-09-08",
                                "Modification_Comment": "updated Description, Name, Relationships, View_Audience, View_Structure"
                            },
                            {
                                "Modification_Name": "CWE Content Team",
                                "Modification_Organization": "MITRE",
                                "Modification_Date": "2010-02-16",
                                "Modification_Comment": "updated Relationships"
                            },
                            {
                                "Modification_Name": "CWE Content Team",
                                "Modification_Organization": "MITRE",
                                "Modification_Date": "2018-03-27",
                                "Modification_Comment": "updated Description, Other_Notes, View_Audience"
                            }
                        ],
                        "Previous_Entry_Name": {
                            "@Date": "2008-09-09",
                            "#text": "Natural Hierarchy"
                        }
                    }
                },
            ]
        },
        "External_References": {
            "External_Reference": [
                {
                    "@Reference_ID": "REF-4",
                    "Author": [
                        "Michael Howard",
                        "David LeBlanc"
                    ],
                    "Title": "C is for cookie, H is for hacker - understanding HTTP only and Secure cookies",
                    "Publication_Year": "2013",
                    "Publication_Month": "--03",
                    "Publication_Day": "---26",
                    "URL": "https://www.troyhunt.com/c-is-for-cookie-h-is-for-hacker/"
                },
            ]
        }
    }
}