#!/usr/bin/env python
import re
import json
import sys

from export_sbom import globals
from export_sbom import data
from export_sbom import config

spdx_deprecated_dict = {
    'AGPL-1.0': 'AGPL-1.0-only',
    'AGPL-3.0': 'AGPL-3.0-only',
    'BSD-2-Clause-FreeBSD': 'BSD-2-Clause',
    'BSD-2-Clause-NetBSD': 'BSD-2-Clause',
    'eCos-2.0': 'NOASSERTION',
    'GFDL-1.1': 'GFDL-1.1-only',
    'GFDL-1.2': 'GFDL-1.2-only',
    'GFDL-1.3': 'GFDL-1.3-only',
    'GPL-1.0': 'GPL-1.0-only',
    'GPL-1.0+': 'GPL-1.0-or-later',
    'GPL-2.0-with-autoconf-exception': 'GPL-2.0-only',
    'GPL-2.0-with-bison-exception': 'GPL-2.0-only',
    'GPL-2.0-with-classpath-exception': 'GPL-2.0-only',
    'GPL-2.0-with-font-exception': 'GPL-2.0-only',
    'GPL-2.0-with-GCC-exception': 'GPL-2.0-only',
    'GPL-2.0': 'GPL-2.0-only',
    'GPL-2.0+': 'GPL-2.0-or-later',
    'GPL-3.0-with-autoconf-exception': 'GPL-3.0-only',
    'GPL-3.0-with-GCC-exception': 'GPL-3.0-only',
    'GPL-3.0': 'GPL-3.0-only',
    'GPL-3.0+': 'GPL-3.0-or-later',
    'LGPL-2.0': 'LGPL-2.0-only',
    'LGPL-2.0+': 'LGPL-2.0-or-later',
    'LGPL-2.1': 'LGPL-2.1-only',
    'LGPL-2.1+': 'LGPL-2.1-or-later',
    'LGPL-3.0': 'LGPL-3.0-only',
    'LGPL-3.0+': 'LGPL-3.0-or-later',
    'Nunit': 'NOASSERTION',
    'StandardML-NJ': 'SMLNJ',
    'wxWindows': 'NOASSERTION'
}


def clean(name):
    newname = re.sub('[;:!*()/,]', '', name)
    newname = re.sub('[ .]', '', newname)
    newname = re.sub('@', '-at-', newname)
    newname = re.sub('_', 'uu', newname)

    return newname


def add_relationship(parent, child, reln):
    mydict = {
        "spdxElementId": data.unquote(parent),
        "relationshipType": data.unquote(reln),
        "relatedSpdxElement": data.unquote(child)
    }
    globals.spdx['relationships'].append(mydict)


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


def write_file(spdx):
    print("Writing SPDX output file {} ... ".format(config.args.output_spdx), end='')

    # globals.spdx["hasExtractedLicensingInfos"] = globals.custom_lics
    try:
        with open(config.args.output_spdx, 'w') as outfile:
            json.dump(spdx, outfile, indent=4, sort_keys=True)

    except Exception as e:
        print('ERROR: Unable to create output report file \n' + str(e))
        sys.exit(3)

    print("Done")


def create_mainproject(proj, ver):
    globals.custom_lic_list = []

    toppkg = clean("SPDXRef-Package-" + proj['name'] + "-" + ver['versionName'])

    # Define TOP Document entries
    globals.spdx["SPDXID"] = "SPDXRef-DOCUMENT"
    globals.spdx["spdxVersion"] = "SPDX-2.2"
    globals.spdx["creationInfo"] = {
        "created": data.unquote(ver['createdAt'].split('.')[0] + 'Z'),
        "creators": ["Tool: Black Duck SPDX export script https://github.com/matthewb66/bd_export_spdx2.2"],
        "licenseListVersion": "3.9",
    }
    if 'description' in proj.keys():
        globals.spdx["creationInfo"]["comment"] = data.unquote(proj['description'])
    globals.spdx["name"] = data.unquote(proj['name'] + '/' + ver['versionName'])
    globals.spdx["dataLicense"] = "CC0-1.0"
    globals.spdx["documentDescribes"] = [toppkg]
    globals.spdx["documentNamespace"] = ver['_meta']['href']
    globals.spdx["downloadLocation"] = "NOASSERTION"
    globals.spdx["filesAnalyzed"] = False
    globals.spdx["copyrightText"] = "NOASSERTION"
    globals.spdx["externalRefs"] = [
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "BlackDuckHub-proj",
                    "referenceLocator": proj["_meta"]["href"],
                },
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "BlackDuckHub-proj-Version",
                    "referenceLocator": ver["_meta"]["href"]
                }
            ]

    add_relationship("SPDXRef-DOCUMENT", toppkg, "DESCRIBES")
    # Add top package for proj version
    #
    projpkg = {
        "SPDXID": data.unquote(toppkg),
        "name": data.unquote(proj['name']),
        "versionInfo": data.unquote(ver['versionName']),
        # "packageFileName":  spdx.quote(package_file),
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "packageComment": "Generated top level package representing Black Duck proj",
        # PackageChecksum: SHA1: 85ed0817af83a24ad8da68c2b5094de69833983c,
        # "licenseConcluded": spdx.quote(lic_string),
        # "licenseDeclared": spdx.quote(lic_string),
        # PackageLicenseComments: <text>Other versions available for a commercial license</text>,
        "filesAnalyzed": False,
        # "ExternalRef: SECURITY cpe23Type {}".format(cpe),
        # "ExternalRef: PACKAGE-MANAGER purl pkg:" + pkg,
        # ExternalRef: PERSISTENT-ID swh swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2,
        # ExternalRef: OTHER LocationRef-acmeforge acmecorp/acmenator/4.1.3-alpha,
        # ExternalRefComment: This is the external ref for Acme,
        "copyrightText": "NOASSERTION",
        # annotations,
    }
    if 'description' in proj.keys():
        projpkg["description"] = data.unquote(proj['description'])
    if 'license' in ver.keys():
        if ver['license']['licenseDisplay'] == 'Unknown License':
            projpkg["licenseDeclared"] = "NOASSERTION"
        else:
            projpkg["licenseDeclared"] = ver['license']['licenseDisplay']
    globals.spdx['packages'].append(projpkg)

    return toppkg


def process_comp(comps_dict, tcomp, comp_data_dict):
    cver = tcomp['componentVersion']
    if cver in comps_dict.keys():
        # ind = compverlist.index(tcomp['componentVersion'])
        bomentry = comps_dict[cver]
    else:
        bomentry = tcomp

    spdxpackage_name = clean(
        "SPDXRef-Package-" + tcomp['componentName'] + "-" + tcomp['componentVersionName'])

    if spdxpackage_name in globals.spdx_ids:
        return spdxpackage_name

    globals.spdx_ids[spdxpackage_name] = 1

    # openhub_url = None

    if cver not in globals.processed_comp_list:
        download_url = "NOASSERTION"

        # fcomp = globals.bd.get_json(tcomp['component'])  # CHECK THIS
        #
        openhub_url = next((item for item in bomentry['_meta']['links'] if item["rel"] == "openhub"), None)
        if config.args.download_loc and openhub_url is not None:
            download_url = data.openhub_get_download(openhub_url['href'])

        copyrights = "NOASSERTION"
        # cpe = "NOASSERTION"
        pkg = "NOASSERTION"
        if not config.args.no_copyrights:
            # copyrights, cpe, pkg = get_orig_data(bomentry)
            copyrights = comp_data_dict[cver]['copyrights']

            if 'origins' in bomentry.keys() and len(bomentry['origins']) > 0:
                orig = bomentry['origins'][0]
                if 'externalNamespace' in orig.keys() and 'externalId' in orig.keys():
                    pkg = data.calculate_purl(orig['externalNamespace'], orig['externalId'])

        package_file = "NOASSERTION"
        if not config.args.no_files:
            package_file = comp_data_dict[cver]['files']

        desc = 'NOASSERTION'
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
            packagesuppliername = packagesuppliername + "NOASSERTION"

        thisdict = {
            "SPDXID": data.unquote(spdxpackage_name),
            "name": data.unquote(tcomp['componentName']),
            "versionInfo": data.unquote(tcomp['componentVersionName']),
            "packageFileName": data.unquote(package_file),
            "description": data.unquote(desc),
            "downloadLocation": data.unquote(download_url),
            "packageHomepage": data.unquote(homepage),
            # PackageChecksum: SHA1: 85ed0817af83a24ad8da68c2b5094de69833983c,
            "licenseConcluded": data.unquote(lic_string),
            "licenseDeclared": data.unquote(lic_string),
            "packageSupplier": packagesuppliername,
            # PackageLicenseComments: <text>Other versions available for a commercial license</text>,
            "filesAnalyzed": False,
            "packageComment": data.unquote(packageinfo),
            # "ExternalRef: SECURITY cpe23Type {}".format(cpe),
            # "ExternalRef: PACKAGE-MANAGER purl pkg:" + pkg,
            # ExternalRef: PERSISTENT-ID swh swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2,
            # ExternalRef: OTHER LocationRef-acmeforge acmecorp/acmenator/4.1.3-alpha,
            # ExternalRefComment: This is the external ref for Acme,
            "copyrightText": data.unquote(copyrights),
            "annotations": annotations,
        }

        if pkg != '':
            thisdict["externalRefs"] = [
                {
                    "referenceLocator": pkg,
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceType": "purl"
                },
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "BlackDuckHub-Component",
                    "referenceLocator": tcomp['component'],
                },
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "BlackDuckHub-Component-Version",
                    "referenceLocator": cver
                }
            ]
            if openhub_url is not None:
                thisdict['externalRefs'].append({
                    "referenceCategory": "OTHER",
                    "referenceType": "OpenHub",
                    "referenceLocator": openhub_url
                })

        globals.spdx['packages'].append(thisdict)
    return spdxpackage_name


def process_comp_relationship(parentname, childname, mtypes):
    reln = False
    for tchecktype in globals.matchtype_depends_dict.keys():
        if tchecktype in mtypes:
            add_relationship(parentname, childname, globals.matchtype_depends_dict[tchecktype])
            reln = True
            break
    if not reln:
        for tchecktype in globals.matchtype_contains_dict.keys():
            if tchecktype in mtypes:
                add_relationship(parentname, childname, globals.matchtype_contains_dict[tchecktype])
                break
