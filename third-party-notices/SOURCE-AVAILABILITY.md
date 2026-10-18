# Bundled native libraries: licenses and source downloads

This directory retains the original license texts and upstream source/build
references for every separately bundled native library in `manifest.json`.
The scanner retains its Python packages' own notices and the Go helper's
notices separately.

## Source mirror

Source for GMP 6.3.0, elfutils 0.194 and the conservatively covered GCC
12.4.0, 14.2.0 and 15.2.0 runtimes is available without registration or charge
from the same public GHCR package as the scanner image. The immutable reference is:

```text
ghcr.io/sourcebastion/sourcebastion-scanner@sha256:88740e3f4ef899fc63aad828497bf0f1cf535fb1878098c66a4ca3a768a2dbf2
```

Download with ORAS, then verify the bundle and original archives:

```sh
oras pull ghcr.io/sourcebastion/sourcebastion-scanner@sha256:88740e3f4ef899fc63aad828497bf0f1cf535fb1878098c66a4ca3a768a2dbf2
printf '%s  native-sources.tar\n' 47c099826215dc33520595a9a51d47df05a633078d28adb9cc8ce9680d896d63 | sha256sum -c -
mkdir native-sources
tar -xf native-sources.tar -C native-sources
(cd native-sources && sha256sum -c SHA256SUMS)
```

The bundle retains five original upstream source archives and four commit-pinned
recipe archives. The Alpine aports snapshots include APKBUILDs and patches for
GMP/elfutils/GCC 15.2.0 on Alpine 3.23 and GCC 14.2.0 on Alpine 3.21.
The rust-musl-cross configuration and musl-cross-make scripts/patches cover
GCC 12.4.0. Per-component `NOTICE.md` files and `manifest.json` identify
original source digests and build references. The recipe snapshots do not
constitute an attestation of historical wheel-build container digests.

## License choices and system packages

License texts are retained verbatim. SourceBastion elects the offered BSD arm
for libev and zstd. For liblzma, XZ's retained licensing summary identifies
the library's 0BSD terms separately from its command-line tools. GMP and the
elfutils libraries retain their LGPL terms. GCC source is covered conservatively;
this makes no conclusion about the scope of the GCC Runtime Library Exception.

Alpine's system packages are separate from wheel-vendored copies. Their package
metadata, notices and source are supplied through Alpine's package/source
channels. This manifest covers the separately wheel-vendored libraries;
it does not inventory all system packages or statically linked code.

Publication and image acceptance are recorded in `docs/M049/` and
https://github.com/sourcebastion/sourcebastion-scanner/issues/164.
