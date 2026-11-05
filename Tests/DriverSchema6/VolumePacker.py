import ast
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile

root = Path(sys.argv[1])
inputs = Path(__file__).resolve().parent
source = (inputs / 'inputs/accepted-sealed-runner.py').read_text()
tree = ast.parse(source)
function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'package_evidence')
namespace = {'shutil': shutil, 'tarfile': tarfile}
exec(compile(ast.Module(body=[function], type_ignores=[]), 'accepted-sealed-runner.py', 'exec'), namespace)
package = namespace['package_evidence']
other = root / 'charged-other'
other.mkdir()
source_dir = Path.cwd() / 'test/nativeproof'
if not source_dir.is_dir():
    source_dir = Path.cwd()
for path in sorted(source_dir.glob('*.go')):
    assert path.is_file() and not path.is_symlink()
    shutil.copyfile(path, other / path.name)
for path in sorted(inputs.iterdir()):
    if path.is_file() and path.suffix in ('.swift', '.json', '.py'):
        shutil.copyfile(path, other / ('harness-' + path.name))
for path in sorted(inputs.glob('inputs/*')):
    if path.is_file():
        shutil.copyfile(path, other / ('input-' + path.name))
base = sum(path.stat().st_size for path in other.iterdir())
assert base <= 16 * 1024 * 1024
with (other / 'remaining-other-allowance.bin').open('wb') as output:
    output.truncate(16 * 1024 * 1024 - base)
images = root / 'charged-images'
images.mkdir()
for index in range(128):
    with (images / f'{index:03d}.jpeg-allowance').open('wb') as output:
        output.truncate(512 * 1024)
payload = root.parent / (root.name + '.evidence.tar')
package(root, payload, root / 'absent-bootstrap.log')
files = sum(path.is_file() for path in root.rglob('*'))
size = payload.stat().st_size
with (other / 'envelope-overflow.bin').open('wb') as output:
    output.truncate(64 * 1024 * 1024)
refused = False
try:
    package(root, root.parent / (root.name + '.overflow.tar'), root / 'absent-bootstrap.log')
except ValueError as error:
    refused = str(error) == 'evidence bound'
assert refused
print(json.dumps({'tarBytes': size, 'files': files, 'imageBytes': 64 * 1024 * 1024,
                  'otherBytes': 16 * 1024 * 1024, 'overflowRefused': refused,
                  'packerSourceSHA256': hashlib.sha256(source.encode()).hexdigest()}))
