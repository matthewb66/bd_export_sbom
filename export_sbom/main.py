#!/usr/bin/env python
import logging
import sys
import os

from blackduck import Client
from export_sbom import globals
from export_sbom import spdx
from export_sbom import config
from export_sbom import process
from export_sbom import projects

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', stream=sys.stderr, level=logging.INFO)
logging.getLogger("requests").setLevel(logging.INFO)
logging.getLogger("urllib3").setLevel(logging.INFO)

url = os.environ.get('BLACKDUCK_URL')
if config.args.blackduck_url:
    url = config.args.blackduck_url

api = os.environ.get('BLACKDUCK_API_TOKEN')
if config.args.blackduck_api_token:
    api = config.args.blackduck_api_token

if config.args.blackduck_trust_certs:
    globals.verify = False

if url == '' or url is None:
    print('BLACKDUCK_URL not set or specified as option --blackduck_url')
    sys.exit(2)

if api == '' or api is None:
    print('BLACKDUCK_API_TOKEN not set or specified as option --blackduck_api_token')
    sys.exit(2)

globals.bd = Client(
    token=api,
    base_url=url,
    verify=globals.verify,  # TLS certificate verification
    timeout=config.args.blackduck_timeout
)


def run():
    print("BLACK DUCK SPDX EXPORT SCRIPT VERSION {}\n".format(globals.script_version))

    config.check_params()

    project, version = projects.check_projver(config.args.project_name, config.args.project_version)
    print("Working on project '{}' version '{}'\n".format(project['name'], version['versionName']))

    bearer_token = globals.bd.session.auth.bearer_token

    if config.args.recursive:
        globals.proj_list = projects.get_all_projects()

    spdx_projname = spdx.spdx_mainproject(project, version)

    if 'hierarchical-components' in globals.bd.list_resources(version):
        hierarchical_bom = globals.bd.get_resource('hierarchical-components', parent=version)
    else:
        hierarchical_bom = []

    process.process_project(version, spdx_projname, hierarchical_bom, bearer_token)

    print("Done")

    spdx.write_spdx_file(globals.spdx)


if __name__ == "__main__":
    run()
