# Synopsys Black Duck - bd_export_sbom
# OVERVIEW

This script is provided under an OSS license (specified in the LICENSE file) to allow users to export SPDX (v2.2) or CycloneDX (v1.3) in JSON format from Black Duck projects.

It does not represent any extension of licensed functionality of Synopsys software itself and is provided as-is, without warranty or liability.

# DESCRIPTION

The script is designed to export SPDX and/or CycloneDX JSON format SBOMs from a Black Duck project.

It relies on the Black Duck `hub-rest-api-python` package to access the Black Duck APIs (see prerequisites below to install and configure this package).

The project name and version need to be specified. If the project name is not matched in the server then the list of projects matching the supplied project string will be displayed (and the script will terminate). If the version name is not matched for the specified project, then the list of all versions will be displayed  (and the script will terminate).

An SPDX output will be created by default, and the output file can optionally be specified; the filename `SPDX-project-version.json` will be used for the default filename if none specified. If the output file already exists, it will be renamed using a numeric extension (for example `.001`).

The optional `--recursive` option will traverse sub-projects to include all leaf components. If not specified, and sub-projects exist in the specified project, then the sub-projects will be skipped.

Other options can be specified to reduce the number of API calls to speed up script execution.

# LATEST UPDATES
## Version 0.1

First implementation

## Version 0.2

Changes to Cyclone JSON output

# PREREQUISITES

1. Pip 3 must be installed.

2. Set the BLACKDUCK_URL and BLACKDUCK_API_TOKEN environment variables to connect to the Black Duck server (alternatively use the `--blackduck_url` and `--blackduck_api_token` options)

# INSTALLATION

Install the package using the command:

        pip3 install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple bd-export-sbom

# USAGE

The program can be invoked as follows:

       usage: bd_export_sbom [-h] [-v] [-o OUTPUT] [-r] [--download_loc] [--no_copyrights] [--no_files] [-b] [--blackduck_url BLACKDUCK_URL]
                               [--blackduck_api_token BLACKDUCK_API_TOKEN] [--blackduck_trust_certs]
                               project_name project_version

       "Export SPDX or CycloneDX JSON format file for the given project and version"

       positional arguments:
         project_name          Black Duck project name
         project_version       Black Duck version name

       optional arguments:
         -h, --help            show this help message and exit
         -v, --version         Print script version and exit
         -o OUTPUT, --output_spdx OUTPUT
                               Output SPDX file name (SPDX JSON format) - default 'SPDX-<proj>-<ver>.json'
         --output_cyclonedx OUTPUT
                               Output CycloneDX file name (JSON format)
         -r, --recursive       Scan sub-projects within projects (default = false)
         --download_loc        Attempt to identify component download link extracted from Openhub (slows down processing - default=false)
         --no_copyrights       Do not export copyright data for components (speeds up processing - default=false)
         --no_files            Do not export file data for components (speeds up processing - default=false)
         -b, --basic           Do not export copyright, download link or package file data (speeds up processing - same as using "--no_copyrights --no_files")
         --blackduck_url BLACKDUCK_URL
                               Black Duck server URL including https://
         --blackduck_api_token BLACKDUCK_API_TOKEN
                               Black Duck API token
         --blackduck_trust_certs
                               Trust Black Duck server certificates if unsigned
         --blackduck_timeout   Change the server connection timeout (default 15 seconds)
         --debug               Add reporting of processed components


If `project_name` does not match a single project then all matching projects will be listed and the script will terminate.

If `version` does not match a single project version then all matching versions will be listed and the script will terminate.

The script will use the environment variables BLACKDUCK_URL and BLACKDUCK_API_TOKEN if they are set. Alternatively use the options `--blackduck_url` and `--blackduck_api_token` to specify them on the command line.

Use the `--blackduck_trust_certs` option to trust the SSL certificate on the Black Duck server if unsigned.

The `--output_spdx outfile` or `-o outfile` options will output in SPDX format to the specified output file. If this file already exists, the previous version will be renamed with a unique number (e.g. .001). The default file name `SPDX-<project>-<version>.json` and SPDX output format will be assumed if no output file specified.

The `--output_cyclonedx outfile` option will output in CycloneDX to the specified output file. If this file already exists, the previous version will be renamed with a unique number (e.g. .001).

The `--recursive` or `-r` option will cause Black Duck sub-projects to be processed, adding the components of sub-projects to the overall SPDX output file. If the processed project version contains sub-projects and this option is not specified, they will be ignored.

The `--download_loc` option will try to extract component download locations from Openhub.net (PackageDownloadLocation tag), increasing the number of API calls and time to complete the script.

The `--no_copyrights` option will stop the processing of component copyright text (PackageCopyrightText tag) reducing the number of API calls and time to complete the script.

The `--no_files` option will stop the processing of component filename (PackageFileName tag) reducing the number of API calls and time to complete the script.

The `--basic` or `-b` option will stop the processing of copyright, download link or package file (same as using `--no_downloads --no_copyrights --no_files` options) reducing the number of API calls and time to complete the script.

# PACKAGE SUPPLIER NAME CONFIGURATION

By default for OSS components, Black Duck with use the external reference (forge name) to populate the 'packageSupplier' SPDX field for components (and the 'externalRefs' 'packageLocator' entries).
For custom components in the BOM, users will need to manually populate this.
Create a custom fields for 'BOM Component' entries with name 'PackageSupplier' and type 'Text'.
Updating the custom field for custom (or KB) components will replace the value in the output SPDX file.
