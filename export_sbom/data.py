#!/usr/bin/env python
import re
from lxml import html
import requests

from export_sbom import globals


def openhub_get_download(oh_url):
    try:
        page = requests.get(oh_url)
        tree = html.fromstring(page.content)

        link = ""
        enlistments = tree.xpath("//a[text()='Project Links:']//following::a[text()='Code Locations:']//@href")
        if len(enlistments) > 0:
            enlist_url = "https://openhub.net" + str(enlistments[0])
            enlist_page = requests.get(enlist_url)
            enlist_tree = html.fromstring(enlist_page.content)
            link = enlist_tree.xpath("//tbody//tr[1]//td[1]/text()")

        if len(link) > 0:
            sp = str(link[0].split(" ")[0]).replace('\n', '')
            #
            # Check format
            protocol = sp.split('://')[0]
            if protocol in ['https', 'http', 'git']:
                return sp

    except Exception as exc:
        print('ERROR: Cannot get openhub data\n' + str(exc))
        return "NOASSERTION"

    return "NOASSERTION"


# 1. translate external_namespace to purl_type [and optionally, purl_namespace]
# 2. split external_id into component_id and version:
#     if: external_namespace not in (npmjs, maven) and splt(external_id by id_separator) > 2 segements
#         split external_id by id_separator on first occurence
#             1: component_id
#             2: version
#     else:
#         split external_id by id_separator on last occurence
#             1: component_id
#             2: version
# 3. purl := "pkg:{:purl_type}"
# 4. if purl_namespace:
#     purl += "/{:purl_namespace}"
# 5. if id_separator in component_id:
#     purl += "/" + 1st part of split(component_id by id_separator)
# 6. if id_separator not in component_id:
#         if external_namespace is pypi
#             then purl += "/" + regexp_replace(lower(component_id), '[-_.]+', '-', 'g')
#             else purl += "/{:component_id}"
#         else
#             purl += "/" + 2nd part of split(component_id by id_separator)
# 7. purl += "@" + 1st part of split(regexp_replace(version, '^\d+:', '') by id_separator)
#    append qualifiers if any:
# 8.    purl += "?"
# 9.    if id_separator in version:
#          then purl += "&arch=" + 2nd part of split(version by id_separator)
# 10.   if version matches /^(\d+):/
#         then purl += "&epoch=" + match_group_1
# 11.   if other qualifier:
#         append uri params
# 12. if subpath is known (i.e. golang import subpath)
#     purl += "#{:subpath}"

def calculate_purl(namespace, extid):
    if namespace in globals.kb_origin_map.keys():
        ns_split = extid.split(globals.kb_origin_map[namespace]['p_sep'])
        if namespace not in ['npmjs', 'maven'] and len(ns_split) > 2:  # 2
            compid, compver = extid.split(globals.kb_origin_map[namespace]['p_sep'], maxsplit=1)
        elif globals.kb_origin_map[namespace]['p_sep'] in extid:
            compid, compver = extid.rsplit(globals.kb_origin_map[namespace]['p_sep'], maxsplit=1)
        else:
            compid, compver = extid, None

        purl = "pkg:" + globals.kb_origin_map[namespace]['p_type']  # 3

        if globals.kb_origin_map[namespace]['p_namespace'] != '':  # 4
            purl += "/" + globals.kb_origin_map[namespace]['p_namespace']

        if globals.kb_origin_map[namespace]['p_sep'] in compid:  # 5
            purl += '/' + '/'.join(unquote(s) for s in compid.split(globals.kb_origin_map[namespace]['p_sep']))
        else:  # 6
            if namespace == 'pypi':
                purl += '/' + unquote(re.sub('[-_.]+', '-', compid.lower()))
            else:
                purl += '/' + unquote(compid)

        qual = {}
        if compver:
            if globals.kb_origin_map[namespace]['p_sep'] in compver:  # 9
                compver, qual['arch'] = compver.split(globals.kb_origin_map[namespace]['p_sep'])

            purl += '@' + unquote(re.sub("^\d+:", '', compver))  # 7

            epoch_m = re.match('^(\d+):', compver)  # 10
            if epoch_m:
                qual['epoch'] = epoch_m[1]

        if qual:
            purl += '?' + '&'.join('='.join([k, unquote(v)]) for k, v in qual.items())  # 8

        return purl
    return ''


def get_package_supplier(comp):
    res = globals.bd.list_resources(comp)
    if 'custom-fields' in res:
        fields_val = globals.bd.get_resource('custom-fields', comp)
    else:
        return ''
    
    sbom_field = next((item for item in fields_val if item['label'] == globals.SBOM_CUSTOM_SUPPLIER_NAME), None)
    
    if sbom_field is not None and len(sbom_field['values']) > 0:
        supplier_name = sbom_field['values'][0]
        return supplier_name
    
    return ''


def get_bom_components(verdict):
    comp_dict = {}
    res = globals.bd.list_resources(verdict)
    # if 'components' not in res:
    if True:
        # Getting the component list via a request is much quicker than the new Client model
        thishref = res['href'] + "/components?limit=5000"
        headers = {
            'accept': "application/vnd.blackducksoftware.bill-of-materials-6+json",
        }
        res = globals.bd.get_json(thishref, headers=headers)
        bom_comps = res['items']
    # else:
    #     bom_comps = globals.bd.get_resource('components', parent=ver)
    for comp in bom_comps:
        if 'componentVersion' not in comp:
            continue
        compver = comp['componentVersion']

        comp_dict[compver] = comp

    return comp_dict


def unquote(name):
    remove_chars = ['"', "'"]
    for i in remove_chars:
        name = name.replace(i, '')
    return name
