from pathlib import Path
import hashlib
import json
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'slice-results'
FILTER = 'ScreenRunner(SliceTests|BSDTests|ChromeBoundaryTests|ReceiptTests|InventoryBoundaryTests)'
FLAGS = ['-Xswiftc', '-DSLICCY_CAPTURE_RUNNER_PROOF', '-Xcc', '-DSLICCY_CAPTURE_RUNNER_PROOF']
BIND = 'Sources/Sliccy/Screen/ScreenRunnerSliceBinding.swift'
BSD = 'Sources/Sliccy/Screen/ScreenRunnerBSD.swift'
OWNER = 'Sources/Sliccy/Screen/ScreenRunnerSystemOwner.swift'
LEDGER = 'Sources/Sliccy/Screen/ScreenRunnerReceiptLedger.swift'
PLAN = [
    ('unique-count', BIND, 'matches.count == 1, let index = matches.first', 'matches.count >= 1, let index = matches.first', 'sameTypeUniqueSelectionAndFullHashPrefixAreMandatory'),
    ('unique-type', BIND, 'members[$0].identity.type == live.type &&', 'true &&', 'sameTypeUniqueSelectionAndFullHashPrefixAreMandatory'),
    ('unique-hash', BIND, 'members[$0].identity.hash == live.hash', 'true', 'sameTypeUniqueSelectionAndFullHashPrefixAreMandatory'),
    ('full-prefix', BIND, 'full.prefix(20) == hash', 'true', 'sameTypeUniqueSelectionAndFullHashPrefixAreMandatory'),
    ('platform', BIND, '!policy.platform || kernel.flags & 0x04000000 != 0', 'true', 'actualSystemCallerUsesCommonBindingAndNeverDropsPlatform'),
    ('slice-offset', BIND, 'value.offset == slice.offset', 'true', 'platformOffsetPathAndIncarnationFailuresRefuseThroughActualBinder'),
    ('path-binding', BIND, 'path == nil || path == kernel.path', 'true', 'platformOffsetPathAndIncarnationFailuresRefuseThroughActualBinder'),
    ('incarnation', BIND, 'before == after', 'true', 'platformOffsetPathAndIncarnationFailuresRefuseThroughActualBinder'),
    ('catalogue-binding', BIND, 'expectedCatalogue == nil || expectedCatalogue == catalogue', 'true', 'platformOffsetPathAndIncarnationFailuresRefuseThroughActualBinder'),
    ('strict-flags', BIND, 'SecCSFlags(rawValue: 25)', 'SecCSFlags(rawValue: 16)', 'everyLiveRoleUsesUniqueSliceAndItsExactPolicy'),
    ('chrome-base-flags', BIND, 'SecCSFlags(rawValue: 9)', 'SecCSFlags(rawValue: 1)', 'everyLiveRoleUsesUniqueSliceAndItsExactPolicy'),
    ('dynamic-flags', BIND, 'policy.chrome ? 0 : 16', '0', 'everyLiveRoleUsesUniqueSliceAndItsExactPolicy'),
    ('chrome-requirement', BIND, 'requirement: ScreenRunnerChromePolicy.requirementText', 'requirement: "wrong"', 'realAdapterAndCallerRoutesForwardExactNativePolicy'),
    ('resolver-controls', BSD, 'sliccy_runner_bsd_select(&observation, pid, &value, &used) == 0', '(sliccy_runner_bsd_select(&observation, pid, &value, &used) == 0 || true)', 'actualResolverRejectsEveryControlFieldAndInvalidTargetBound'),
    ('code-boundary', OWNER, 'let verified = try check()', 'let verified = Code(identifier: identifier, path: path, hash: hash)', 'actualResolverAndCodeBoundaryFeedInventoryWithoutBypass'),
    ('bsd-brackets', BSD, 'before.sample == after.sample', 'true', 'actualBindingRejectsChangedCredentialsAndIncarnation'),
    ('windowserver-controls', BSD, 'before.controlsAgreed, after.controlsAgreed,', 'true,', 'actualBindingRejectsChangedCredentialsAndIncarnation'),
    ('windowserver-tuple', BSD, 'sliccy_runner_bsd_windowserver(&a, &b) != 0', 'true', 'actualResolverAndCodeBoundaryFeedInventoryWithoutBypass'),
    ('receipt-key', LEDGER, 'previous.key == key', 'true', 'everyComparedChangeImmediatelyStartsAFullReceipt'),
    ('receipt-count', LEDGER, 'previous.count += 1', 'previous.count += 0', 'identicalReceiptsRetainExactCountsAndActualTimes'),
    ('receipt-failure-flush', LEDGER, 'deliveries = drainLocked()\n                deliveries.append', 'deliveries = []\n                deliveries.append', 'failureFlushesEveryStreamAndCannotBeAggregated'),
    ('receipt-boolean', LEDGER, 'CFGetTypeID(boolean) == CFBooleanGetTypeID()', 'true', 'boundedRowsStreamsAndNumericBooleansRetireEvidence'),
    ('receipt-cutoff', LEDGER, 'let failed = delivering != 0', 'let failed = false', 'finalCutoffNeverWaitsForBlockedDelivery'),
]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert os.environ.get('RUNNER_OS') == 'macOS' and os.environ.get('RUNNER_ARCH') == 'ARM64'
    OUT.mkdir(mode=0o700, exist_ok=False)
    files = sorted(p for base in ['Sources', 'Tests', 'script', 'docs', '.github/workflows'] for p in (ROOT / base).rglob('*') if p.is_file()) + [ROOT / 'Package.swift']
    inputs = {str(p.relative_to(ROOT)): digest(p) for p in files}
    (OUT / 'inputs.json').write_text(json.dumps({'source': os.environ['GITHUB_SHA'], 'run': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'files': inputs}, indent=2) + '\n')
    (OUT / 'plan.json').write_text(json.dumps(PLAN, indent=2) + '\n')
    results = []
    def run(name, args, limit):
        start = time.monotonic()
        try:
            value = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=limit)
        except subprocess.TimeoutExpired as error:
            for stream in ['stdout', 'stderr']: (OUT / (name + '.' + stream)).write_bytes(getattr(error, stream) or b'')
            results.append({'name': name, 'args': args, 'timeout': limit, 'exit': None})
            (OUT / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            raise
        for stream in ['stdout', 'stderr']: (OUT / (name + '.' + stream)).write_bytes(getattr(value, stream))
        results.append({'name': name, 'args': args, 'exit': value.returncode, 'seconds': time.monotonic() - start,
            'stdout': hashlib.sha256(value.stdout).hexdigest(), 'stderr': hashlib.sha256(value.stderr).hexdigest()})
        (OUT / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        return value
    build = ['/usr/bin/xcrun', 'swift', 'build', '--build-tests', *FLAGS]
    test = ['/usr/bin/xcrun', 'swift', 'test', '--skip-build', *FLAGS, '--filter']
    success = False
    try:
        assert run('baseline-build', build, 600).returncode == 0
        assert run('baseline-components', test + [FILTER], 120).returncode == 0
        for name, path, old, new, selected in PLAN:
            target = ROOT / path
            original = target.read_bytes()
            assert original.decode().count(old) == 1, name
            try:
                target.write_text(original.decode().replace(old, new))
                assert run(name + '-build', build, 180).returncode == 0, name
                value = run(name + '-runtime', test + [selected], 60)
                output = value.stdout + value.stderr
                assert value.returncode == 1 and b'Expectation failed' in output and selected.encode() in output, name
            finally:
                target.write_bytes(original)
            assert run(name + '-restored-build', build, 180).returncode == 0, name
            assert run(name + '-restored-runtime', test + [selected], 60).returncode == 0, name
        assert run('restored-components', test + [FILTER], 120).returncode == 0
        success = True
    finally:
        after = {path: digest(ROOT / path) for path in inputs}
        (OUT / 'source-after.json').write_text(json.dumps(after, indent=2) + '\n')
        assert inputs == after
        (OUT / 'summary.json').write_text(json.dumps({'success': success, 'mutations': len(PLAN), 'sourceUnchanged': True,
            'scope': 'synthetic byte/struct/Security-adapter fixtures; no native process, Security, GUI or capture query'}, indent=2) + '\n')

if __name__ == '__main__':
    main()
