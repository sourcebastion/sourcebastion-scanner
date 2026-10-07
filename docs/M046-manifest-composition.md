# M046 S03 canonical static Python manifests

`compose_source` extends the reviewed requirements composer with built-in static
PEP621, setup.cfg and literal setup.py grammar. A controller-held Source is
traversed/discovered once; manifests reuse the read-hash cache and Source
deadline. Discovery and both adapters share the actual semantic visit counter,
occurrence limits and selection-node accounting. The final epoch validation and
full typed structure preflight run after all adapters, before output admission.
No customer callback, project execution, installation, host-target fallback or
forge API is introduced. Production scan routing remains unchanged.

Explicit static application name/version evidence creates a located project
root and application. A containing folder alone creates none. Static dependency
metadata without application identity retains unknown project ownership and a
manifest analysis scope. Separate manifests are separately evidenced; they are
not silently merged by folder. Requirements in the same folder do not borrow
manifest ownership. Equal purls retain distinct occurrences and source locations.

Runtime, build, test and optional declarations retain their scopes, requested
extras and groups. Pins require compatible exact source declarations in the
same scope, group and narrowly proved marker context. Conflicting or unproved
overlapping contexts retain unselected occurrences and visible partial coverage.
No package edges or installed environments are inferred. The contract also
refuses selection evidence from another scope/group.

Requires-Python is typed applicability evidence, independent of dependency
markers and optional-group activation. Only an explicit full recorded target
version evaluates its range; a minor-only target cannot invent a patch version.
Default policy preserves unknown applicability. Build requirements have their
own interpreter/platform context and do not borrow project compatibility or
marker inputs. A project target does not establish a build target; build markers
with missing inputs remain unknown.
Optional groups remain unknown unless another condition proves them inactive;
this slice does not implement selection of optional groups. Missing marker
inputs stay unknown. All original conditions remain in canonical evidence.

A recognized, explicit empty project is distinct from a tool-metadata-only
configuration. Dynamic or unknown dependency controls remain unsupported. A
failed or unsupported manifest cannot be promoted by successful requirements
parsing. Source epoch or shared job budget failures clear roots, applications,
conditions and packages together. Inventory/graph/environment/export/matching
statuses retain their separate meanings.

Python lock adapters, provider composition, non-Python canonical support, full
rich corpus agreement, CycloneDX/Grype, platform persistence and release/dev
acceptance remain open. This production module is not yet a production scanner
route. S03 and M046 remain incomplete.
