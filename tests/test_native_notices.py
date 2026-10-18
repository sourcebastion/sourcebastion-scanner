"""Notice retention is byte-bound; it must not imply source qualification."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('notice_artifacts', ROOT / 'scripts/scanner_artifacts.py')
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


@pytest.fixture
def notices(tmp_path, monkeypatch):
    root = tmp_path / 'notices'
    directory = root / 'example-1.0'
    directory.mkdir(parents=True)
    (directory / 'LICENSE').write_bytes(b'Owned license text')
    data = {'schema_version': 1, 'components': [{
        'id': 'example-1.0', 'license': 'MIT',
        'license_files': {'LICENSE': hashlib.sha256(b'Owned license text').hexdigest()},
        'source_url': 'https://example.invalid/source.tar.gz',
        'source_sha256': 'b' * 64, 'native_sha256': ['a' * 64]}]}
    (root / 'manifest.json').write_text(json.dumps(data))
    monkeypatch.setattr(artifacts, 'NOTICES', root)
    return root, data


def test_retained_notice_covers_original_bytes_and_refuses_new_library(notices):
    artifacts.verify_native_notices([{'sha256': 'a' * 64}])
    with pytest.raises(ValueError, match='lack retained notices'):
        artifacts.verify_native_notices([{'sha256': 'c' * 64}])


@pytest.mark.parametrize('change', ['missing', 'same-size-change', 'symlink'])
def test_missing_changed_or_redirected_license_refuses(notices, change):
    root, _ = notices
    path = root / 'example-1.0/LICENSE'
    if change == 'same-size-change':
        path.write_bytes(b'Other license text')
    else:
        path.unlink()
        if change == 'symlink':
            other = root / 'elsewhere'
            other.write_bytes(b'Owned license text')
            path.symlink_to(other)
    with pytest.raises((ValueError, FileNotFoundError)):
        artifacts.verify_native_notices([{'sha256': 'a' * 64}])


@pytest.mark.parametrize('change', ['traversal', 'no-license', 'no-source', 'ambiguous'])
def test_incomplete_or_ambiguous_binding_refuses(notices, change):
    root, data = notices
    component = data['components'][0]
    if change == 'traversal':
        component['license_files'] = {'../LICENSE': 'b' * 64}
    elif change == 'no-license':
        component['license_files'] = {}
    elif change == 'no-source':
        component['source_sha256'] = ''
    else:
        other = copy.deepcopy(component)
        other['id'] = 'example-2.0'
        (root / 'example-2.0').mkdir()
        (root / 'example-2.0/LICENSE').write_bytes(b'Owned license text')
        data['components'].append(other)
    (root / 'manifest.json').write_text(json.dumps(data))
    with pytest.raises(ValueError):
        artifacts.verify_native_notices([{'sha256': 'a' * 64}])


def test_committed_notices_cover_both_reviewed_architectures():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / '.github/bundled-native-libraries.json').read_text())
    for libraries in manifest['targets'].values():
        artifacts.verify_native_notices(libraries)


def test_redirected_component_directory_refuses(notices):
    root, _ = notices
    original = root / 'example-1.0'
    renamed = root / 'elsewhere'
    original.rename(renamed)
    original.symlink_to(renamed, target_is_directory=True)
    with pytest.raises(ValueError, match='directory must not be a symlink'):
        artifacts.verify_native_notices([{'sha256': 'a' * 64}])


def test_runtime_comparison_accounts_for_standard_wheel_spreading():
    # Exercise the helper embedded in the actual image runtime assertion.
    import ast
    import re
    script = (ROOT / 'scripts/assert-image-runtime.sh').read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
    tree = ast.parse(script)
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == 'installed_native_path')
    namespace = {'re': re}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), '<runtime helper>', 'exec'), namespace)
    normalize = namespace['installed_native_path']
    assert normalize('semgrep-1.180.0.data/purelib/semgrep/bin/libs/libelf.so.1') == 'semgrep/bin/libs/libelf.so.1'
    assert normalize('example-1.data/platlib/example.libs/libfoo.so.1') == 'example.libs/libfoo.so.1'
    for path in ['cryptography.libs/libgcc_s.so.1', 'example-1.data/scripts/libfoo.so.1',
                 'nested/example-1.data/purelib/libfoo.so.1']:
        assert normalize(path) == path
