"""Pure source gate, not a Swift compiler. Unknown conditions fail closed."""
from pathlib import Path
import hashlib

FLAG = 'SLICCY_CAPTURE_RUNNER_PROOF'

def product_projection(text, *, debug=False, arch='arm64', proof_flags=()):
    allowed = {'DEBUG', FLAG, 'SLICCY_NATIVE_SCREEN_PROOF', 'SLICCY_SNAPSHOT_PROOF',
               'SLICCY_HOSTED_PID_PROOF', 'SLICCY_UNIVERSAL_SLICE_PROOF'}
    def condition(expression):
        parts = expression.split(' || ')
        values = []
        for part in parts:
            negate = part.startswith('!')
            name = part[1:] if negate else part
            if name in ('arch(arm64)', 'arch(x86_64)'):
                value = name == 'arch(' + arch + ')'
            elif name in allowed:
                value = debug if name == 'DEBUG' else name in proof_flags and name != FLAG
            else:
                raise ValueError('projection-unknown-condition:' + name)
            values.append(not value if negate else value)
        return any(values)
    active, frames, output = True, [], []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith('#if '):
            choice = condition(stripped[4:])
            frames.append([active, choice, False])
            active = active and choice
        elif stripped.startswith('#elseif '):
            if not frames or frames[-1][2]:
                raise ValueError('projection-elseif')
            parent, taken, _ = frames[-1]
            choice = condition(stripped[8:])
            active = parent and not taken and choice
            frames[-1][1] = taken or choice
        elif stripped == '#else':
            if not frames or frames[-1][2]:
                raise ValueError('projection-else')
            parent, taken, _ = frames[-1]
            active = parent and not taken
            frames[-1][1:] = [True, True]
        elif stripped == '#endif':
            if not frames:
                raise ValueError('projection-unbalanced-end')
            active = frames.pop()[0]
        elif active:
            output.append(line)
    if frames:
        raise ValueError('projection-unbalanced-if')
    return ''.join(output)


def verify(root, accepted):
    records = {}
    files = sorted((root/'Sources').rglob('*.swift'))
    for path in files:
        relative = path.relative_to(root).as_posix()
        original = accepted.get(relative, '')
        actual = path.read_text()
        left, right = product_projection(original), product_projection(actual)
        if left != right:
            raise AssertionError('build17-product-projection:' + relative)
        records[relative] = {'productSHA256': hashlib.sha256(right.encode()).hexdigest(),
                             'sourceChanged': original != actual}
    if set(accepted)-{path.relative_to(root).as_posix() for path in files}:
        raise AssertionError('build17-product-source-deleted')
    return records
