# Organization workflow management moved to platform

Starting with scanner 2.1.4, organization discovery, inherited configuration and
workflow installation live in [sourcebastion-platform](https://github.com/sourcebastion/sourcebastion-platform).
Install that project and replace `ez-appsec org-sync` with
`sourcebastion-org-sync`, retaining `--org`, `--config-repo` and `--dry-run`.
The old scanner command exits with migration instructions and performs no
provider requests.

See the [operator guide](https://github.com/sourcebastion/sourcebastion-platform/blob/main/docs/organization-workflows.md)
for permissions and dry-run/install examples. Existing workflow files and the
legacy configuration repository name remain compatible. The platform generates
workflows using the reusable [sourcebastion-action](https://github.com/sourcebastion/sourcebastion-action);
the scanner only scans source and produces reports.

Provider provisioning helpers (`scripts/provision.py`, `scripts/mint-token.py`,
`github/scripts/*`, `github/templates/scan.yml`) already have maintained platform
counterparts. Use those from the platform repository. The scanner's obsolete
App Install Provisioner workflow is removed; it no longer accepts installation
dispatches. No credentials or existing customer workflows are moved automatically.
