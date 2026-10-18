# Bundled native libraries: source availability

This directory retains license texts and upstream source/build references for
the separately bundled native libraries listed in `manifest.json`. It does not
replace the Python packages' own notices or the Go helper's existing notices.

**SourceBastion-controlled source mirror: pending M049/S02.** The upstream
references are available in each component's `NOTICE.md` and the manifest,
with archive SHA-256 digests. Complete corresponding-source qualification,
including the actual compiler build scripts and patches, is not yet accepted.
This status notice is not a completed written source offer. Do not describe an
image containing these notices alone as M049 distribution-qualified.

The applicable license texts are retained verbatim. For libev and zstd,
SourceBastion elects the offered BSD arm. For liblzma, the retained XZ licensing
summary identifies the library's 0BSD terms separately from command-line tools.
GMP and the elfutils libraries retain their LGPL terms. GCC runtime source
coverage is treated conservatively; no conclusion about the scope of the GCC
Runtime Library Exception is asserted here.

Alpine's system packages are separate from wheel-vendored copies. Their package
metadata, notices and source are supplied through Alpine's package/source
channels. This directory's manifest covers wheel-vendored files, not a claim
that all installed system packages or all statically linked code are covered.

Track current source publication and acceptance in
https://github.com/sourcebastion/sourcebastion-scanner/issues/164 and
`docs/M049/` in the source repository. Once the source mirror is verified, this
file must name its actual retrievable immutable reference and download command;
an anticipated tag or a broken location is not a substitute.
