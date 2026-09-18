# Maintaining GitHub Action pins

Dependabot updates third-party Actions in root `.github/workflows` files. This
repository also ships workflows from `dashboard/`, `github/dashboard/`, and
`github/templates/`, and generates one from `ez_appsec/org_manager.py`.
Dependabot does not discover every one of those locations.

The weekly `Action pin audit` workflow closes that gap. It resolves every
human-readable version comment (for example `# v4`) through the upstream
repository and compares the resulting commit with every active, shipped, and
generated pin. It is read-only and fails visibly when a tag moved or a lookup
cannot be verified. A failure is a review prompt, not permission to trust the
new tag automatically.

To update a pin:

1. Review the upstream release and confirm that the tag resolves within the
   expected Action repository.
2. Replace the commit for every occurrence of that Action/version pair. Find
   them with `rg 'uses: OWNER/REPOSITORY@' .github dashboard github ez_appsec`.
3. Keep the trailing version comment; it is the key the audit resolves.
4. Run `pytest -q tests/test_workflow_action_pins.py`.

The consistency test rejects a partial update when an Action/version pair is
copied into multiple locations. The scheduled audit covers pairs that exist
only outside root workflows and therefore never receive a Dependabot pull
request.
