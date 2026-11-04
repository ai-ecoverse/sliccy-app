from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'slice-results'
FILTER = 'ScreenRunner(SliceTests|BSDTests|ChromeBoundaryTests|ReceiptTests|InventoryBoundaryTests|ChildReceiptTests|OwnerEvidenceTests|JournalTests)'
FLAGS = ['-Xswiftc', '-DSLICCY_NATIVE_SCREEN_PROOF', '-Xswiftc', '-DSLICCY_CAPTURE_RUNNER_PROOF', '-Xcc', '-DSLICCY_CAPTURE_RUNNER_PROOF']
BIND = 'Sources/Sliccy/Screen/ScreenRunnerSliceBinding.swift'
BSD = 'Sources/Sliccy/Screen/ScreenRunnerBSD.swift'
OWNER = 'Sources/Sliccy/Screen/ScreenRunnerSystemOwner.swift'
LEDGER = 'Sources/Sliccy/Screen/ScreenRunnerReceiptLedger.swift'
CHILD = 'Sources/Sliccy/Screen/ScreenRunnerChildReceipts.swift'
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
    ('cli-capture-delivery', CHILD, 'batch.deliver(to: { _, _ in }, sliceOutput: receipts.record, loss: receipts.lost)', 'batch.deliver(to: { _, _ in }, sliceOutput: { _ in }, loss: receipts.lost)', 'actualCLICaptureDeliversSuccessAndRefusalReceipts'),
    ('cli-signal-delivery', CHILD, 'lock.withEvidence(output: { _, _ in }, sliceOutput: receipts.record, loss: receipts.lost, operation: check)', 'lock.withEvidence(output: { _, _ in }, sliceOutput: { _ in }, loss: receipts.lost, operation: check)', 'actualCLISignalDeliversAfterUnlockOnSuccessAndRefusal'),
    ('cli-refusal-receipt', CHILD, 'defer { batch.collectSlice(boundary(pid: pid, identity: identity, signal: value, passed: passed)) }', 'defer { if passed { batch.collectSlice(boundary(pid: pid, identity: identity, signal: value, passed: passed)) } }', 'actualCLISignalDeliversAfterUnlockOnSuccessAndRefusal'),
]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def named_assertions(value, selected):
    if value is None or value.returncode != 1:
        return []
    output = re.sub(rb'\x1b\[[0-9;]*m', b'', value.stdout + value.stderr).decode('utf-8', errors='replace')
    if any(marker in output for marker in ['Caught error:', 'SIGKILL', 'unexpected signal', 'Fatal error:', 'fatal error:', 'error: Exited']):
        return []
    pattern = r'Test ' + re.escape(selected) + r'\(\) recorded an issue at [^\n]+: Expectation failed:[^\n]*'
    return re.findall(pattern, output)


def overlay(root, row, run, build, test):
    name, path, old, new, selected = row
    target = root / path
    original = target.read_bytes()
    assert original.decode().count(old) == 1, name
    compiled = runtime = restored_build = restored_runtime = None
    try:
        target.write_text(original.decode().replace(old, new))
        compiled = run(name + '-build', build, 180)
        if compiled.returncode == 0:
            runtime = run(name + '-runtime', test + [selected], 60)
    finally:
        target.write_bytes(original)
    restored_build = run(name + '-restored-build', build, 180)
    if restored_build.returncode == 0:
        restored_runtime = run(name + '-restored-runtime', test + [selected], 60)
    assertions = named_assertions(runtime, selected)
    red = compiled.returncode == 0 and bool(assertions)
    green = restored_build.returncode == 0 and restored_runtime is not None and restored_runtime.returncode == 0
    unchanged = target.read_bytes() == original
    assert unchanged, name
    return {'name': name, 'selected': selected, 'compileExit': compiled.returncode,
        'runtimeExit': runtime.returncode if runtime is not None else None,
        'namedAssertions': assertions, 'runtimeRed': red,
        'restoredCompileExit': restored_build.returncode,
        'restoredRuntimeExit': restored_runtime.returncode if restored_runtime is not None else None,
        'restoredGreen': green, 'sourceRestored': unchanged,
        'originalSHA256': hashlib.sha256(original).hexdigest(), 'restoredSHA256': digest(target),
        'valid': red and green and unchanged}


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
    overlays = []
    try:
        assert run('production-build', ['/usr/bin/xcrun', 'swift', 'build', '--scratch-path', '.build/production-exclusion'], 600).returncode == 0
        assert run('baseline-build', build, 600).returncode == 0
        assert run('baseline-components', test + [FILTER], 120).returncode == 0
        for row in PLAN:
            overlays.append(overlay(ROOT, row, run, build, test))
            (OUT / 'overlays.json').write_text(json.dumps(overlays, indent=2) + '\n')
        final = run('restored-components', test + [FILTER], 120)
        success = final.returncode == 0 and len(overlays) == len(PLAN) and all(row['valid'] for row in overlays)
    finally:
        after = {path: digest(ROOT / path) for path in inputs}
        (OUT / 'source-after.json').write_text(json.dumps(after, indent=2) + '\n')
        assert inputs == after
        (OUT / 'summary.json').write_text(json.dumps({'success': success, 'mutations': len(PLAN), 'completedOverlays': len(overlays),
            'validRuntimeRedRestoredGreen': sum(row['valid'] for row in overlays), 'sourceUnchanged': True,
            'scope': 'synthetic byte/struct/Security-adapter fixtures; no native process, Security, GUI or capture query'}, indent=2) + '\n')

    return success

if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
