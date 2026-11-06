#!/usr/bin/env python3
"""Pure gate: every hosted.py precondition before Go / network / subprocess.

Stubs: RUNNER_*/GITHUB_*/DRIVER_COMPONENT_* env (injected), subprocess, urllib.
Executes asserts against real Tests/DriverSchema6 inputs.json, fixtures, tar, and maps.
Run from repo root or pass the DriverSchema6 directory as argv[1].
"""
from __future__ import annotations

import hashlib
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def catalog() -> list[dict]:
    """Every assert in hosted.py with the file/object it checks."""
    return [
        {'line': 21, 'assert': "RUNNER_ENVIRONMENT==github-hosted && RUNNER_OS==macOS && RUNNER_ARCH==ARM64", 'file': 'env:RUNNER_*', 'preGo': True},
        {'line': 22, 'assert': "GITHUB_REF==refs/heads/proof/independent-driver-schema6-v1 && EVENT==push", 'file': 'env:GITHUB_*', 'preGo': True},
        {'line': 30, 'assert': 'DRIVER_COMPONENT_SHARD_COUNT==6 && index consistent', 'file': 'env:DRIVER_COMPONENT_SHARD_*', 'preGo': True},
        {'line': 32, 'assert': 'checked_suite_groups(suite_ledger)', 'file': 'shards.json', 'preGo': True},
        {'line': 41, 'assert': 'each manifest["inputs"] digest', 'file': 'inputs.json keys → Tests/DriverSchema6 relative paths', 'preGo': True},
        {'line': 43, 'assert': 'fixtureSHA256 == ReceiptFixture.swift', 'file': 'ReceiptFixture.swift', 'preGo': True},
        {'line': 44, 'assert': 'collectorTestSHA256 == test_harness.py', 'file': 'test_harness.py', 'preGo': True},
        {'line': 45, 'assert': 'clockFixtureSHA256 == ClockFixture.swift', 'file': 'ClockFixture.swift', 'preGo': True},
        {'line': 46, 'assert': 'build16FixtureSources digests', 'file': 'build16FixtureSources map paths', 'preGo': True},
        {'line': 47, 'assert': 'normalizationFixtureSources digests', 'file': 'normalizationFixtureSources map paths', 'preGo': True},
        {'line': 48, 'assert': 'scheduleSources digests', 'file': 'scheduleSources map paths', 'preGo': True},
        {'line': 49, 'assert': 'refusalFixtureSources digests', 'file': 'refusalFixtureSources map paths', 'preGo': True},
        {'line': 50, 'assert': 'actualEncoderSources digests', 'file': 'repo-root Paths in actualEncoderSources', 'preGo': True},
        {'line': 59, 'assert': 'remaining timeout > 0', 'file': 'runtime clock inside command()', 'preGo': False},
        {'line': 62, 'assert': 'stdout/stderr size bounds', 'file': 'command outputs', 'preGo': False},
        {'line': 77, 'assert': 'tar member path safety', 'file': 'any expanded tar', 'preGo': False},
        {'line': 80, 'assert': 'tar size/member limits', 'file': 'expanded tar', 'preGo': False},
        {'line': 92, 'assert': 'collector-selftest returncode==0', 'file': 'test_harness.py via subprocess', 'preGo': False},
        {'line': 95, 'assert': 'Go toolchain tarball length+sha', 'file': 'network go1.26.5 download', 'preGo': False},
        {'line': 102, 'assert': 'go version string', 'file': 'go binary', 'preGo': False},
        {'line': 108, 'assert': 'expanded driver files == manifest[files]', 'file': 'inputs/driver-source.tar.gz', 'preGo': True, 'note': 'pure gate hashes tar members without Go'},
        {'line': 111, 'assert': 'foundation-compile returncode==0', 'file': 'ReceiptFixture.swift + ledger sources', 'preGo': False},
        {'line': 113, 'assert': 'foundation-encode stdout bounds', 'file': 'receipt fixture binary', 'preGo': False},
        {'line': 118, 'assert': 'clock-foundation-compile', 'file': 'ClockFixture.swift', 'preGo': False},
        {'line': 120, 'assert': 'clock-foundation-encode', 'file': 'clock fixture binary', 'preGo': False},
        {'line': 124, 'assert': 'refusal-foundation-compile', 'file': 'Refusal*.swift', 'preGo': False},
        {'line': 126, 'assert': 'refusal-foundation-encode', 'file': 'refusal fixture binary', 'preGo': False},
        {'line': 130, 'assert': 'surface-foundation-compile', 'file': 'Surface*.swift', 'preGo': False},
        {'line': 132, 'assert': 'surface-foundation-encode', 'file': 'surface fixture binary', 'preGo': False},
        {'line': 137, 'assert': 'build16-foundation-compile', 'file': 'build16FixtureSources', 'preGo': False},
        {'line': 139, 'assert': 'build16-foundation-encode', 'file': 'build16 fixture binary', 'preGo': False},
        {'line': 146, 'assert': 'go-baseline-compile', 'file': './test/nativeproof', 'preGo': False},
        {'line': 153, 'assert': 'pre-mutation source map == manifest[files]', 'file': 'expanded driver dir', 'preGo': False},
        {'line': 157, 'assert': 'mutation old-string occurs once', 'file': 'mutant target file', 'preGo': False},
        {'line': 170, 'assert': 'post-restore map == manifest[files]', 'file': 'expanded driver dir', 'preGo': False},
        {'line': 175, 'assert': 'restored-compile', 'file': 'mutant file restored', 'preGo': False},
        {'line': 177, 'assert': 'restored-runtime exact test', 'file': 'mutant test', 'preGo': False},
        {'line': 182, 'assert': 'post-loop map == manifest[files]', 'file': 'expanded driver dir', 'preGo': False},
        {'line': 184, 'assert': 'full-restored-compile', 'file': './test/nativeproof', 'preGo': False},
        {'line': 186, 'assert': 'post-full-suite map', 'file': 'expanded driver dir', 'preGo': False},
        {'line': 193, 'assert': 'gofmt each file', 'file': 'each driver .go', 'preGo': False},
        {'line': 201, 'assert': 'formatted tree hashes', 'file': 'formatted driver dir', 'preGo': False},
        {'line': 203, 'assert': 'formatted-final-compile', 'file': './test/nativeproof', 'preGo': False},
        {'line': 209, 'assert': 'final restore map', 'file': 'expanded driver dir', 'preGo': False},
        {'line': 211, 'assert': 'all mutations validRed', 'file': 'mutation-results', 'preGo': False},
    ]


def run_pre_go(root: Path = ROOT, repo: Path = REPO, env: dict | None = None) -> list[dict]:
    """Mirror hosted.py L21–51 and L108 without Go/network/subprocess."""
    sys.path.insert(0, str(root))
    from partition import select_mutations
    from suite_schedule import checked_suite_groups

    e = {
        'RUNNER_ENVIRONMENT': 'github-hosted',
        'RUNNER_OS': 'macOS',
        'RUNNER_ARCH': 'ARM64',
        'GITHUB_REF': 'refs/heads/proof/independent-driver-schema6-v1',
        'GITHUB_EVENT_NAME': 'push',
        'DRIVER_COMPONENT_SHARD_INDEX': '0',
        'DRIVER_COMPONENT_SHARD_COUNT': '6',
        'GITHUB_SHA': '0' * 40,
    }
    if env:
        e.update(env)

    results: list[dict] = []

    def check(line: int, name: str, file_checked: str, fn) -> None:
        row = {'line': line, 'assert': name, 'file': file_checked, 'ok': False, 'detail': None}
        try:
            fn()
            row['ok'] = True
            results.append(row)
        except Exception as err:
            row['detail'] = f'{type(err).__name__}: {err}'
            results.append(row)
            raise AssertionError(json.dumps(row)) from err

    def env21():
        assert e['RUNNER_ENVIRONMENT'] == 'github-hosted' and e['RUNNER_OS'] == 'macOS' and e['RUNNER_ARCH'] == 'ARM64'

    check(21, 'RUNNER_ENVIRONMENT/OS/ARCH hosted macOS ARM64', 'env:RUNNER_*', env21)

    def env22():
        assert e['GITHUB_REF'] == 'refs/heads/proof/independent-driver-schema6-v1' and e['GITHUB_EVENT_NAME'] == 'push'

    check(22, 'GITHUB_REF independent-driver-schema6-v1 and EVENT push', 'env:GITHUB_REF/EVENT', env22)

    manifest = json.loads((root / 'inputs.json').read_text())

    def shard30():
        shard_index = int(e['DRIVER_COMPONENT_SHARD_INDEX'])
        assert e['DRIVER_COMPONENT_SHARD_COUNT'] == '6' and str(shard_index) == e['DRIVER_COMPONENT_SHARD_INDEX']

    check(30, 'DRIVER_COMPONENT_SHARD_COUNT==6 and index consistent', 'env:DRIVER_COMPONENT_SHARD_*', shard30)

    suite_ledger = json.loads((root / 'shards.json').read_text())

    def shards32():
        checked_suite_groups(suite_ledger)

    check(32, 'checked_suite_groups(shards.json)', 'shards.json', shards32)

    all_mutations = json.loads((root / 'mutants.json').read_text())
    shard_index = int(e['DRIVER_COMPONENT_SHARD_INDEX'])
    selected_mutations, selected_ids, universe_ids = select_mutations(all_mutations, shard_index, 6)

    def partition38():
        assert len(universe_ids) == len(all_mutations)
        assert set(selected_ids).issubset(set(universe_ids))
        assert len(selected_mutations) == len(selected_ids)

    check(38, 'select_mutations partition well-formed', 'mutants.json+partition.py', partition38)

    for name, digest in manifest['inputs'].items():
        def make(n=name, d=digest):
            def fn():
                got = sha((root / n).read_bytes())
                assert got == d, f'{n}: got {got} expected {d}'
            return fn
        check(41, f'inputs[{name!r}] digest', name, make())

    def fixture43():
        got = sha((root / 'ReceiptFixture.swift').read_bytes())
        assert got == manifest['fixtureSHA256'], f'got {got} expected {manifest["fixtureSHA256"]}'

    check(43, 'fixtureSHA256 == ReceiptFixture.swift', 'ReceiptFixture.swift', fixture43)

    def collector44():
        got = sha((root / 'test_harness.py').read_bytes())
        assert got == manifest['collectorTestSHA256'], f'got {got} expected {manifest["collectorTestSHA256"]}'

    check(44, 'collectorTestSHA256 == test_harness.py', 'test_harness.py', collector44)

    def clock45():
        got = sha((root / 'ClockFixture.swift').read_bytes())
        assert got == manifest['clockFixtureSHA256'], f'got {got} expected {manifest["clockFixtureSHA256"]}'

    check(45, 'clockFixtureSHA256 == ClockFixture.swift', 'ClockFixture.swift', clock45)

    for name, digest in manifest['build16FixtureSources'].items():
        def make(n=name, d=digest):
            def fn():
                got = sha((root / n).read_bytes())
                assert got == d, f'{n}: got {got} expected {d}'
            return fn
        check(46, f'build16FixtureSources[{name}]', name, make())

    for name, digest in manifest['normalizationFixtureSources'].items():
        def make(n=name, d=digest):
            def fn():
                got = sha((root / n).read_bytes())
                assert got == d, f'{n}: got {got} expected {d}'
            return fn
        check(47, f'normalizationFixtureSources[{name}]', name, make())

    for name, digest in manifest['scheduleSources'].items():
        def make(n=name, d=digest):
            def fn():
                got = sha((root / n).read_bytes())
                assert got == d, f'{n}: got {got} expected {d}'
            return fn
        check(48, f'scheduleSources[{name}]', name, make())

    for name, digest in manifest['refusalFixtureSources'].items():
        def make(n=name, d=digest):
            def fn():
                got = sha((root / n).read_bytes())
                assert got == d, f'{n}: got {got} expected {d}'
            return fn
        check(49, f'refusalFixtureSources[{name}]', name, make())

    for name, digest in manifest['actualEncoderSources'].items():
        def make(n=name, d=digest):
            def fn():
                path = repo / n
                assert path.is_file(), n
                got = sha(path.read_bytes())
                assert got == d, f'{n}: got {got} expected {d}'
            return fn
        check(50, f'actualEncoderSources[{name}]', name, make())

    def tar_files_108():
        with tarfile.open(root / 'inputs/driver-source.tar.gz') as tar:
            got = {m.name: sha(tar.extractfile(m).read()) for m in tar.getmembers() if m.isfile()}
        assert got == manifest['files'], 'tar member digests != manifest[files]'

    check(108, 'driver-source.tar.gz member digests == manifest[files]', 'inputs/driver-source.tar.gz', tar_files_108)
    return results


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else ROOT
    repo = Path(argv[2]).resolve() if len(argv) > 2 else (root.parents[1] if root.name == 'DriverSchema6' else REPO)
    try:
        rows = run_pre_go(root, repo)
        print(json.dumps({'ok': True, 'checks': len(rows), 'failed': 0, 'rows': rows}, indent=2))
        return 0
    except AssertionError as err:
        try:
            payload = json.loads(str(err))
        except Exception:
            payload = {'ok': False, 'detail': str(err)}
        print(json.dumps({
            'ok': False,
            'failed': payload,
            'catalogPreGo': [c for c in catalog() if c.get('preGo')],
        }, indent=2))
        return 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
