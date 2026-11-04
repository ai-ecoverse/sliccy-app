from pathlib import Path
import contextlib
import io
import json
import runpy
import hashlib
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def ordinary_source(source):
    frames = []
    keep = True
    result = []
    for line in source.splitlines():
        directive = line.strip()
        if directive.startswith('#if '):
            selected = directive == '#if SLICCY_CAPTURE_RUNNER_PROOF'
            frames.append((selected, keep))
            if selected: keep = False
            elif keep: result.append(line)
        elif directive == '#else':
            selected, parent = frames[-1]
            if selected: keep = parent
            elif keep: result.append(line)
        elif directive == '#endif':
            selected, parent = frames.pop()
            if not selected and keep: result.append(line)
            keep = parent
        elif keep: result.append(line)
    assert not frames
    return re.sub(r'\s+', '', '\n'.join(result)).encode()


class CLIReceiptSourceTests(unittest.TestCase):
    def test_normal_child_body_matches_accepted_source(self):
        child = (ROOT / 'Sources/Sliccy/Screen/ScreenChild.swift').read_text()
        self.assertEqual(hashlib.sha256(ordinary_source(child)).hexdigest(), '0b81663f0c15e38af67c99c574fb045547bf92cae46e9f500d60ecb9bf7f52f9')

    def test_fixed_journal_cap_and_nominal_model_match(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runpy.run_path(str(ROOT / 'Tests/RunnerSlice/volume.py'), run_name='__main__')
        model = json.loads(output.getvalue())
        self.assertEqual(model['caseJournalCap'], 1048576)
        self.assertEqual(model['nominalStableMargin'], 506880)
        self.assertLess(model['worstMarginWithAggregation'], 0)
        source = (ROOT / 'Sources/Sliccy/Screen/ScreenRunnerJournal.swift').read_text()
        self.assertTrue(source.startswith('#if SLICCY_CAPTURE_RUNNER_PROOF'))
        self.assertIn('data.count <= 4096, bytes + data.count <= 1048576', source)

    def test_actual_session_connection_child_chain_has_required_sink(self):
        screen = ROOT / 'Sources/Sliccy/Screen'
        app = (screen / 'ScreenRunnerProofApp.swift').read_text()
        connection = (screen / 'ScreenRunnerConnection.swift').read_text()
        child = (screen / 'ScreenChild.swift').read_text()
        identity = (screen / 'ScreenRunnerProcessIdentity.swift').read_text()
        self.assertIn('ScreenRunnerConnection(receipts: .init(record: sliceRecord,', app)
        self.assertIn('ScreenChild.runner(join: join, bootstrap: handshake.bootstrapRecord(), policy: policy, receipts: receipts,', connection)
        self.assertIn('guard case .runner(let receipts) = source else { throw ScreenFailure.incompatible }', child)
        self.assertIn('ScreenRunnerChildChecks.capture(pid: pid, hash: hash, receipts: runnerReceipts)', child)
        self.assertIn('ScreenRunnerChildChecks.signalUnderLock(lock, receipts: runnerReceipts)', child)
        self.assertNotRegex(identity, r'sliceEvidence:[^\n]*= \{ _ in \}')

if __name__ == '__main__':
    unittest.main()
