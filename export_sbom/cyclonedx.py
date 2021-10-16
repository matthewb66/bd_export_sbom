#!/usr/bin/env python
import re
import json
import sys

from export_sbom import globals
from export_sbom import config

def clean_for_cdx(name):
    newname = re.sub('[;:!*()/,]', '', name)
    newname = re.sub('[ .]', '', newname)
    newname = re.sub('@', '-at-', newname)
    newname = re.sub('_', 'uu', newname)

    return newname


def add_relationship(parent, child, reln):
    mydict = {
        "spdxElementId": quote(parent),
        "relationshipType": quote(reln),
        "relatedSpdxElement": quote(child)
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


def write_cdx_file(spdx):
    print("Writing SPDX output file {} ... ".format(config.args.output_spdx), end='')

    try:
        with open(config.args.output_spdx, 'w') as outfile:
            json.dump(spdx, outfile, indent=4, sort_keys=True)

    except Exception as e:
        print('ERROR: Unable to create output report file \n' + str(e))
        sys.exit(3)

    print("Done")


def cdx_mainproject(proj, ver):
    globals.spdx_custom_lics = []

    toppkg = clean_for_spdx("SPDXRef-Package-" + proj['name'] + "-" + ver['versionName'])

    # Define TOP Document entries
    globals.spdx["SPDXID"] = "SPDXRef-DOCUMENT"
    globals.spdx["spdxVersion"] = "SPDX-2.2"
    globals.spdx["creationInfo"] = {
        "created": quote(ver['createdAt'].split('.')[0] + 'Z'),
        "creators": ["Tool: Black Duck SPDX export script https://github.com/matthewb66/bd_export_spdx2.2"],
        "licenseListVersion": "3.9",
    }
    if 'description' in proj.keys():
        globals.spdx["creationInfo"]["comment"] = quote(proj['description'])
    globals.spdx["name"] = quote(proj['name'] + '/' + ver['versionName'])
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
        "SPDXID": quote(toppkg),
        "name": quote(proj['name']),
        "versionInfo": quote(ver['versionName']),
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
        projpkg["description"] = quote(proj['description'])
    if 'license' in ver.keys():
        if ver['license']['licenseDisplay'] == 'Unknown License':
            projpkg["licenseDeclared"] = "NOASSERTION"
        else:
            projpkg["licenseDeclared"] = ver['license']['licenseDisplay']
    globals.spdx['packages'].append(projpkg)

    return toppkg
