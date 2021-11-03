#!/usr/bin/env python
script_version = "0.1"

processed_comp_list = []
custom_lic_list = []
cdx_lics_dict = {}

# The name of a custom attribute which should override the default package supplier
SBOM_CUSTOM_SUPPLIER_NAME = "PackageSupplier"

usage_dict = {
    "SOURCE_CODE": "CONTAINS",
    "STATICALLY_LINKED": "STATIC_LINK",
    "DYNAMICALLY_LINKED": "DYNAMIC_LINK",
    "SEPARATE_WORK": "OTHER",
    "MERELY_AGGREGATED": "OTHER",
    "IMPLEMENTATION_OF_STANDARD": "OTHER",
    "PREREQUISITE": "HAS_PREREQUISITE",
    "DEV_TOOL_EXCLUDED": "DEV_TOOL_OF"
}

matchtype_depends_dict = {
    "FILE_DEPENDENCY_DIRECT": "DEPENDS_ON",
    "FILE_DEPENDENCY_TRANSITIVE": "DEPENDS_ON",
}

matchtype_contains_dict = {
    "FILE_EXACT": "CONTAINS",
    "FILE_FILES_ADDED_DELETED_AND_MODIFIED": "CONTAINS",
    "FILE_DEPENDENCY": "CONTAINS",
    "FILE_EXACT_FILE_MATCH": "CONTAINS",
    "FILE_SOME_FILES_MODIFIED": "CONTAINS",
    "MANUAL_BOM_COMPONENT": "CONTAINS",
    "MANUAL_BOM_FILE": "CONTAINS",
    "PARTIAL_FILE": "CONTAINS",
    "BINARY": "CONTAINS",
    "SNIPPET": "OTHER",
}

kb_origin_map = {
    "alpine": {"p_type": "apk", "p_namespace": "alpine", "p_sep": "/"},
    "android": {"p_type": "apk", "p_namespace": "android", "p_sep": ":"},
    "bitbucket": {"p_type": "bitbucket", "p_namespace": "", "p_sep": ":"},
    "bower": {"p_type": "bower", "p_namespace": "", "p_sep": "/"},
    "centos": {"p_type": "rpm", "p_namespace": "centos", "p_sep": "/"},
    "clearlinux": {"p_type": "rpm", "p_namespace": "clearlinux", "p_sep": "/"},
    "cpan": {"p_type": "cpan", "p_namespace": "", "p_sep": "/"},
    "cran": {"p_type": "cran", "p_namespace": "", "p_sep": "/"},
    "crates": {"p_type": "cargo", "p_namespace": "", "p_sep": "/"},
    "dart": {"p_type": "pub", "p_namespace": "", "p_sep": "/"},
    "debian": {"p_type": "deb", "p_namespace": "debian", "p_sep": "/"},
    "fedora": {"p_type": "rpm", "p_namespace": "fedora", "p_sep": "/"},
    "gitcafe": {"p_type": "gitcafe", "p_namespace": "", "p_sep": ":"},
    "github": {"p_type": "github", "p_namespace": "", "p_sep": ":"},
    "gitlab": {"p_type": "gitlab", "p_namespace": "", "p_sep": ":"},
    "gitorious": {"p_type": "gitorious", "p_namespace": "", "p_sep": ":"},
    "golang": {"p_type": "golang", "p_namespace": "", "p_sep": ":"},
    "hackage": {"p_type": "hackage", "p_namespace": "", "p_sep": "/"},
    "hex": {"p_type": "hex", "p_namespace": "", "p_sep": "/"},
    "maven": {"p_type": "maven", "p_namespace": "", "p_sep": ":"},
    "mongodb": {"p_type": "rpm", "p_namespace": "mongodb", "p_sep": "/"},
    "npmjs": {"p_type": "npm", "p_namespace": "", "p_sep": "/"},
    "nuget": {"p_type": "nuget", "p_namespace": "", "p_sep": "/"},
    "opensuse": {"p_type": "rpm", "p_namespace": "opensuse", "p_sep": "/"},
    "oracle_linux": {"p_type": "rpm", "p_namespace": "oracle", "p_sep": "/"},
    "packagist": {"p_type": "composer", "p_namespace": "", "p_sep": ":"},
    "pear": {"p_type": "pear", "p_namespace": "", "p_sep": "/"},
    "photon": {"p_type": "rpm", "p_namespace": "photon", "p_sep": "/"},
    "pypi": {"p_type": "pypi", "p_namespace": "", "p_sep": "/"},
    "redhat": {"p_type": "rpm", "p_namespace": "redhat", "p_sep": "/"},
    "ros": {"p_type": "deb", "p_namespace": "ros", "p_sep": "/"},
    "rubygems": {"p_type": "gem", "p_namespace": "", "p_sep": "/"},
    "ubuntu": {"p_type": "deb", "p_namespace": "ubuntu", "p_sep": "/"},
    "yocto": {"p_type": "yocto", "p_namespace": "", "p_sep": "/"},
}


spdx = {
    'packages': [],
    'relationships': [],
    'snippets': [],
    'hasExtractedLicensingInfos': [],
}

cdx = {
    'metadata': {},
    'components': [],
    'dependencies': [],
}

spdx_ids = {}
cdx_ids = {}
proj_list = []

verify = True

bd = None
