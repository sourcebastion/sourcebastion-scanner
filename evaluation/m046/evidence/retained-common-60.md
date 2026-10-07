# Retained common 60-case comparison

`retained-common-60-current-oracle.tar.gz` publishes the already measured four
profiles and 480 attempts, re-compared against the current 64-case independent
oracle. It contains 2,971 regular files and 24 synthetic symlinks encoded as
data, about 172 MB uncompressed / 7 MB compressed. No tool binaries, customer
sources or production bindings are included. The archive was built with
descriptor-bound snapshots and a 256 MiB total byte ceiling.

Verify its adjacent SHA256 file, then the archive's `SHA256SUMS` before using
the retained data. All archived members are regular files. `SYMLINKS.json`
preserves synthetic fixture link targets as data; it does not authorize following
outside-root inputs. Restore links only after verifying their exact paths and
targets against the pinned corpus, in a fresh disposable evidence directory.

The archive includes `current-report.json`, `current-report.md`, a portable
`recompare-current-retained.py`, the three exact reference comparator/corpus
source files and tool pins. The comparator imports only those trusted evaluation
modules from a checkout and checks them against commit
`4774e199279d9267fb9f7cc59f3834289bf9c4b1` before and after comparison. It does
not execute candidates or customer source. It requires Linux/Python and git;
its own address-space/CPU/output/wall ceilings remain enforced.

After checksum verification and extraction of the regular files into a fresh
directory, restore only the 24 corpus-defined links with this controller helper.
Pass the trusted checkout and extracted evidence directory as its two arguments:

```sh
rtk proxy python3 - /path/to/trusted-checkout /path/to/verified-evidence <<'PY'
import hashlib, json, pathlib, sys
checkout, evidence = map(lambda p: pathlib.Path(p).resolve(), sys.argv[1:])
report = json.loads((evidence / 'current-report.json').read_text())
for name, checksum in report['source_sha256'].items():
    assert hashlib.sha256((checkout / name).read_bytes()).hexdigest() == checksum
sys.path.insert(0, str(checkout))
from evaluation.m046.corpus import CORPUS
fixtures = {row['id']: row for row in CORPUS}
expected = {}
for profile, candidate in report['candidates'].items():
    for row in candidate['attempts']:
        fixture, repeat = row['fixture'], row['repetition']
        for name, target in fixtures[fixture]['symlinks'].items():
            expected[f'{profile}/{fixture}/{repeat}/source/{name}'] = target
links = json.loads((evidence / 'SYMLINKS.json').read_text())
assert links == expected and len(links) == 24
for name, target in sorted(expected.items()):
    relative = pathlib.PurePosixPath(name)
    assert not relative.is_absolute() and '..' not in relative.parts
    path = evidence / name
    assert not any(p.is_symlink() for p in path.parents)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
print('restored exactly 24 known synthetic links; no targets were read')
PY
```

The portable replay accepts explicit `--source`, `--retained` and `--output`
paths. `--source` points to a trusted checkout with the pinned comparator bytes;
`--retained` points to the verified/restored archive directory. Output is written
under `--output/current-comparison`. The complete example is:

```sh
rtk proxy python3 recompare-current-retained.py --source /path/to/trusted-checkout --retained /path/to/verified-evidence --output /path/to/new-output
```

Portable report SHA256:
`d0a9b50a499dac7718a49043fa9eaddfa2045423896b97af117449aed473149b`.
Its 480 attempt records and all other evidence fields exactly equal the prior
reviewed `9a408fc1...f649f` report; only the builder hash changes because private
absolute paths became CLI arguments. A different script byte hash is not a
new tool measurement or new oracle.

The profiles retain 60 common input cases; four later cases remain unevaluated.
Basic package/edge agreements are 38/32/38/43 and also-exact applications are
37/9/38/42 for Syft/cdxgen/SCALIBR/projection. Rich full-contract agreement is
zero. Empty negatives count as agreements; these are not accuracy percentages.
Projection inputs deliberately transform exact pins and strip hash options,
with original/derived paths and hashes retained. Stock inputs are unchanged.

Historical trace admission stays `manual-review-required`. Missing/failed raw
outputs remain invalid. Current-oracle replay never upgrades offline/isolation,
native ARM64, vulnerability accuracy or production acceptance. The initial
50-case archive remains historical; this archive supplies the common 60-case
evidence used by the current architecture comparison.
