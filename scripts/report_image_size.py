"""Record architecture and uncompressed size of the image actually tested."""
import json
from pathlib import Path
import sys

image = json.loads(Path(sys.argv[1]).read_text())
expected_arch = sys.argv[2]
if image["Architecture"] != expected_arch or image["Os"] != "linux":
    raise SystemExit(f"expected linux/{expected_arch}, got {image['Os']}/{image['Architecture']}")
print(f"| Architecture | Uncompressed MiB | Layers |")
print("|---|---:|---:|")
print(f"| {expected_arch} | {image['Size'] / 1024**2:.1f} | {len(image['RootFS']['Layers'])} |")
