#!/usr/bin/env python
import re
import json
import sys
import datetime

from export_sbom import globals
from export_sbom import config
from export_sbom import data


def clean(name):
    newname = re.sub('[;:!*()/,]', '', name)
    newname = re.sub('[ .]', '', newname)
    newname = re.sub('@', '-at-', newname)
    newname = re.sub('_', 'uu', newname)

    return newname


def add_relationship(parent, child, reln):
    # {
    #   "ref": "acme-app",
    #   "dependsOn": [
    #     "pkg:maven/org.acme/web-framework@1.0.0",
    #     "pkg:maven/org.acme/persistence@3.1.0"
    #   ]
    # },
    mydict = {
        "ref": parent,
        "dependsOn": [
            child,
        ]
    }
    globals.cdx['dependencies'].append(mydict)


def add_snippet():
    # "snippets": [{
    # 	"SPDXID": "SPDXRef-Snippet",
    # 	"comment": "This snippet was identified as significant and highlighted in this Apache-2.0 file, when a
    # 	commercial scanner identified it as being derived from file foo.c in package xyz which is licensed under
    # 	GPL-2.0.",
    # 	"copyrightText": "Copyright 2008-2010 John Smith",
    # 	"licenseComments": "The concluded license was taken from package xyz, from which the snippet was copied
    # 	into the current file. The concluded license information was found in the COPYING.txt file in package xyz.",
    # 	"licenseConcluded": "GPL-2.0-only",
    # 	"licenseInfoInSnippets": ["GPL-2.0-only"],
    # 	"name": "from linux kernel",
    # 	"ranges": [{
    # 		"endPointer": {
    # 			"lineNumber": 23,
    # 			"reference": "SPDXRef-DoapSource"
    # 		},
    # 		"startPointer": {
    # 			"lineNumber": 5,
    # 			"reference": "SPDXRef-DoapSource"
    # 		}
    # 	}, {
    # 		"endPointer": {
    # 			"offset": 420,
    # 			"reference": "SPDXRef-DoapSource"
    # 		},
    # 		"startPointer": {
    # 			"offset": 310,
    # 			"reference": "SPDXRef-DoapSource"
    # 		}
    # 	}],
    # 	"snippetFromFile": "SPDXRef-DoapSource"
    # }],
    pass


def write_file(cdx):
    print("Writing CYCLONEDX output file {} ... ".format(config.args.output_cyclonedx), end='')

    try:
        with open(config.args.output_cyclonedx, 'w') as outfile:
            json.dump(cdx, outfile, indent=4, sort_keys=True)

    except Exception as e:
        print('ERROR: Unable to create output report file \n' + str(e))
        sys.exit(3)

    print("Done")


def create_mainproject(proj, ver):
    # globals.spdx_custom_lics = []

    appname = clean(proj['name'] + "-" + ver['versionName'])
    arr = ver['_meta']['href'].split('/')
    uuid = ''
    if len(arr) > 7:
        uuid = arr[7]

    licname = ''
    for lic in ver['license']['licenses']:
        if licname != '':
            licname += " AND "
        licname += lic['name']

    nowtime = datetime.datetime.now()
    nowtime = nowtime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # Define TOP Document entries
    globals.cdx = {
        "bomFormat": "CycloneDX",
        "specVersion":"1.3",
        "serialNumber": f'urn:uuid:{uuid}',
        "version": 1,
        "manufacture": {
            "name": "Synopsys Black Duck",
            "url": "https://www.synopsys.com/software-integrity/security-testing/software-composition-analysis.html",
            # "contact": "",
        },
        "supplier": {
            "name": "",
            "url": "",
            "contact": "",
        },
        "components": [
            {
                "type": "application",
                "name": clean(proj['name']),
                "version": clean(ver['versionName']),
                # "swid": {
                #     "tagId": "swidgen-cebab27e-da95-213c-8b73-d1d3afcb806f_2.0.0",
                #     "name": "Acme Commerce Suite",
                #     "version": "2.0.0"
                # },
                "components": [],
            },
        ],
        # globals.cdx['metadata'] = {}
        "metadata": {
            # 'timestamp': data.unquote(ver['createdAt'].split('.')[0] + 'Z'),
            'timestamp': data.unquote(nowtime),
            "tools": [
                {
                    "vendor": "Synopsys Inc.",
                    "name": "Black Duck SBOM Exporter",
                    "version": "0.1",
                }
            ],
            "licenseListVersion": "3.9",
            "licenses": [
                {
                    "name": licname,
                }
            ],
            "externalReferences": [
                {
                    "url": ver['_meta']['href'],
                    "comment": "Black Duck BOM location",
                    "type": "bom",
                }
            ],
        },
    }

    # add_relationship("SPDXRef-DOCUMENT", appname, "DESCRIBES")
    return appname


def process_comp(comps_dict, tcomp, comp_data_dict):
    cver = tcomp['componentVersion']
    if cver in comps_dict.keys():
        # ind = compverlist.index(tcomp['componentVersion'])
        bomentry = comps_dict[cver]
    else:
        bomentry = tcomp

    cdxpackage_name = clean(
        tcomp['componentName'] + "-" + tcomp['componentVersionName'])

    pkg = ""

    if cdxpackage_name in globals.cdx_ids:
        return pkg

    globals.cdx_ids[cdxpackage_name] = 1
    # openhub_url = None

    if cver not in globals.processed_comp_list:
        download_url = ""

        # fcomp = globals.bd.get_json(tcomp['component'])  # CHECK THIS
        #
        openhub_url = next((item for item in bomentry['_meta']['links'] if item["rel"] == "openhub"), None)
        if config.args.download_loc and openhub_url is not None:
            download_url = data.openhub_get_download(openhub_url['href'])

        copyrights = ""
        # cpe = "NOASSERTION"
        pkg = ""
        if not config.args.no_copyrights:
            # copyrights, cpe, pkg = get_orig_data(bomentry)
            copyrights = comp_data_dict[cver]['copyrights']

            if 'origins' in bomentry.keys() and len(bomentry['origins']) > 0:
                orig = bomentry['origins'][0]
                if 'externalNamespace' in orig.keys() and 'externalId' in orig.keys():
                    pkg = data.calculate_purl(orig['externalNamespace'], orig['externalId'])

        package_file = ""
        if not config.args.no_files:
            package_file = comp_data_dict[cver]['files']

        desc = ''
        if 'description' in tcomp.keys():
            desc = re.sub('[^a-zA-Z.()\d\s\-:]', '', bomentry['description'])

        annotations = comp_data_dict[cver]['comments']
        lic_string = comp_data_dict[cver]['licenses']

        component_package_supplier = ''

        homepage = comp_data_dict[cver]['url']
        bom_package_supplier = comp_data_dict[cver]['supplier']

        packageinfo = "This is a"

        if bomentry['componentType'] == 'CUSTOM_COMPONENT':
            packageinfo = packageinfo + " custom component"
        if bomentry['componentType'] == 'SUB_PROJECT':
            packageinfo = packageinfo + " sub project"
        else:
            packageinfo = packageinfo + "n open source component from the Black Duck Knowledge Base"

        if len(bomentry['matchTypes']) > 0:
            first_type = bomentry['matchTypes'][0]
            if first_type == 'MANUAL_BOM_COMPONENT':
                packageinfo = packageinfo + " which was manually added"
            else:
                packageinfo = packageinfo + " which was automatically detected"
                if first_type == 'FILE_EXACT':
                    packageinfo = packageinfo + " as a direct file match"
                elif first_type == 'SNIPPET':
                    packageinfo = packageinfo + " as a code snippet"
                elif first_type == 'FILE_DEPENDENCY_DIRECT':
                    packageinfo = packageinfo + " as a directly declared dependency"
                elif first_type == 'FILE_DEPENDENCY_TRANSITIVE':
                    packageinfo = packageinfo + " as a transitive dependency"

        packagesuppliername = ''

        if bom_package_supplier is not None and len(bom_package_supplier) > 0:
            packageinfo = packageinfo + ", the PackageSupplier was provided by the user at the BOM level"
            packagesuppliername = packagesuppliername + bom_package_supplier
            pkg = "supplier:{}/{}/{}".format(bom_package_supplier.replace("Organization: ", ""), tcomp['componentName'],
                                             tcomp['componentVersionName'])
        elif component_package_supplier is not None and len(component_package_supplier) > 0:
            packageinfo = packageinfo + ", the PackageSupplier was populated in the component"
            packagesuppliername = packagesuppliername + component_package_supplier
            pkg = "supplier:{}/{}/{}".format(component_package_supplier.replace("Organization: ", ""),
                                             tcomp['componentName'], tcomp['componentVersionName'])
        elif bomentry['origins'] is not None and len(bomentry['origins']) > 0:
            packagesuppliername = packagesuppliername + "Organization: " + bomentry['origins'][0]['externalNamespace']
            packageinfo = packageinfo + ", the PackageSupplier was based on the externalNamespace"
        else:
            packageinfo = packageinfo + ", the PackageSupplier was not populated"
            packagesuppliername = packagesuppliername + ""

        # TO DO - use packagesuppliername somewhere

        thisdict = {
            "bom-ref": pkg,
            "type": "component",
        #     "group": "org.acme",
            "name": data.unquote(tcomp['componentName']),
            "version": data.unquote(tcomp['componentVersionName']),
            "description": data.unquote(desc),
        #     "publisher": "Apache",
            "purl": pkg,
            "licenses": globals.cdx_lics_dict[tcomp['componentVersion']],
        #         {
        #             "license": {
        #                 "id": data.unquote(lic_string),
        #                 "text": {
        #                     "contentType": "text/plain",
        # #                   "encoding": "base64",
        #                     "content": "",
        #                 },
        # #               "url": "https://www.apache.org/licenses/LICENSE-2.0.txt"
        #             }
        #         }
            "copyright": data.unquote(copyrights),
            "supplier": {
                "name": data.unquote(packagesuppliername),
                "url": [
                    data.unquote(homepage),
        #             "https://example.net"
                ],
        #         "contact": [
        #             {
        #                 "name": "Example Support AMER Distribution",
        #                 "email": "support@example.com",
        #                 "phone": "800-555-1212"
        #             },
        #             {
        #                 "name": "Example Support APAC",
        #                 "email": "support@apac.example.com"
        #             }
        #         ]
            },
        #     "author": "Example Development Labs - Alpha Team",
            "externalReferences": [
                {
                    "url": tcomp['componentVersion'],
                    "type": "other",
                    "comment": packageinfo,
                },
            ]
        }

        globals.cdx['components'][0]['components'].append(thisdict)

    return pkg


def process_comp_relationship(parentname, childname, mtypes):
    reln = False
    for tchecktype in globals.matchtype_depends_dict.keys():
        if tchecktype in mtypes:
            add_relationship(parentname, childname, globals.matchtype_depends_dict[tchecktype])
            reln = True
            break
    # if not reln:
    #     for tchecktype in globals.matchtype_contains_dict.keys():
    #         if tchecktype in mtypes:
    #             add_relationship(parentname, childname, globals.matchtype_contains_dict[tchecktype])
    #             break
