from pathlib import Path
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / 'script/runner-proof'
sys.path.insert(0, str(SCRIPTS))
import capture_stage_root as subject
import capture_stage as adapter


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.source = self.home / 'Sliccy.app'
        binary = self.source / 'Contents/MacOS/Sliccy'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'fixed approved executable')
        binary.chmod(0o700)
        (self.source / 'Contents/Info.plist').write_bytes(b'fixed metadata')
        self.expected = adapter.bundle_manifest(self.source, 'a' * 40, 'identifier "ai.sliccy.mac"')
        self.rows = []
        self.journal = subject.Journal(write=self.record)

    def record(self, data):
        self.rows.append(json.loads(data))
        return len(data)

    def model_immutable(self, fd, directory):
        value = os.fstat(fd)
        self.assertEqual(stat.S_ISDIR(value.st_mode), directory)
        if not directory:
            self.assertTrue(stat.S_ISREG(value.st_mode))
            self.assertEqual(value.st_nlink, 1)
        self.assertEqual(value.st_mode & 0o022, 0)
        return value

    def descriptors(self):
        target = self.home / 'target'
        target.mkdir(mode=0o700)
        source = os.open(self.source, subject.DIR_FLAGS)
        destination = os.open(target, subject.DIR_FLAGS)
        self.addCleanup(os.close, source)
        self.addCleanup(os.close, destination)
        return target, source, destination

    def test_actual_copy_is_non_executable_until_verified_boundary(self):
        target, source, destination = self.descriptors()
        with patch.object(subject, 'immutable', self.model_immutable):
            copied = subject.copy_tree(source, destination, self.expected, time.monotonic() + 5)
            self.assertEqual(copied['files'], self.expected['files'])
            self.assertEqual((target / 'Contents/MacOS/Sliccy').stat().st_mode & 0o777, 0o444)
            subject.enable_executables(destination, self.expected)
            self.assertEqual((target / 'Contents/MacOS/Sliccy').stat().st_mode & 0o777, 0o555)
            self.assertEqual((target / 'Contents/Info.plist').stat().st_mode & 0o777, 0o444)

    def test_symlink_and_hardlink_sources_never_copy_outside_content(self):
        for mode in ('symlink', 'hardlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as case:
                outside = Path(case) / 'outside'
                outside.write_bytes(b'outside sentinel')
                extra = self.source / 'Contents/extra'
                if mode == 'symlink':
                    extra.symlink_to(outside)
                else:
                    os.link(outside, extra)
                target = Path(case) / 'target'
                target.mkdir()
                source = os.open(self.source, subject.DIR_FLAGS)
                destination = os.open(target, subject.DIR_FLAGS)
                try:
                    with patch.object(subject, 'immutable', self.model_immutable), self.assertRaises(ValueError):
                        subject.copy_tree(source, destination, self.expected, time.monotonic() + 5)
                    self.assertEqual(outside.read_bytes(), b'outside sentinel')
                    self.assertFalse((target / 'Contents/extra').exists())
                finally:
                    os.close(source); os.close(destination); extra.unlink()

    def test_changed_checksum_or_deadline_never_enables_execution(self):
        target, source, destination = self.descriptors()
        (self.source / 'Contents/MacOS/Sliccy').write_bytes(b'X' * len(b'fixed approved executable'))
        with patch.object(subject, 'immutable', self.model_immutable), self.assertRaisesRegex(ValueError, 'checksum'):
            subject.copy_tree(source, destination, self.expected, time.monotonic() + 5)
        self.assertEqual((target / 'Contents/MacOS/Sliccy').stat().st_mode & 0o111, 0)
        with self.assertRaisesRegex(ValueError, 'deadline'):
            subject.copy_tree(source, destination, self.expected, time.monotonic() - 1)

    def test_cleanup_uses_retained_inode_and_refuses_outside_symlinks(self):
        library = self.home / 'library'
        library.mkdir()
        staged = library / 'SliccyProof-1'
        staged.mkdir(mode=0o755)
        outside = self.home / 'outside'
        outside.write_bytes(b'preserved')
        identity = [staged.stat().st_dev, staged.stat().st_ino]
        fd = os.open(library, subject.DIR_FLAGS)
        try:
            with patch.object(subject, 'immutable', self.model_immutable):
                with self.assertRaisesRegex(ValueError, 'root-replaced'):
                    subject.remove_owned(fd, staged.name, [identity[0], identity[1] + 1], self.journal)
                (staged / 'link').symlink_to(outside)
                with self.assertRaisesRegex(ValueError, 'file-type'):
                    subject.remove_owned(fd, staged.name, identity, self.journal)
                self.assertEqual(outside.read_bytes(), b'preserved')
                (staged / 'link').unlink()
                subject.remove_owned(fd, staged.name, identity, self.journal)
                self.assertFalse(staged.exists())
        finally:
            os.close(fd)

    def test_every_fixed_static_step_failure_records_command_and_both_tails(self):
        for step in ('staging-os-version', 'staged-role', 'staged-designated-requirement', 'staged-code-directory'):
            with self.subTest(step=step):
                self.rows.clear()
                result = subprocess.CompletedProcess(['/usr/bin/codesign'], 3, b'output', b'failure')
                with patch.object(subject.subprocess, 'run', return_value=result), self.assertRaises(ValueError):
                    subject.command(self.journal, step, ['/usr/bin/codesign', '--fixed'], time.monotonic() + 5)
                self.assertEqual(self.rows[0]['step'], step)
                self.assertEqual(self.rows[0]['arguments'], ['--fixed'])
                self.assertEqual(self.rows[0]['tool'], '/usr/bin/codesign')
                self.assertEqual(self.rows[1]['exitStatus'], 3)
                self.assertEqual(self.rows[1]['stdoutTail'], 'output')
                self.assertEqual(self.rows[1]['stderrTail'], 'failure')

    def test_actual_stage_failure_removes_owned_directory_and_never_executes_subject(self):
        library = self.home / 'library'
        library.mkdir()
        fd = os.open(library, subject.DIR_FLAGS)
        calls = []
        def fail(journal, step, args, deadline):
            calls.append(args)
            raise ValueError('forced signature failure')
        try:
            with patch.object(subject, 'immutable', self.model_immutable), patch.object(subject, 'command', fail):
                with self.assertRaisesRegex(ValueError, 'signature failure'):
                    subject.stage(fd, 'SliccyProof-1', self.expected, self.journal, time.monotonic() + 5)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], '/usr/bin/codesign')
            self.assertFalse((library / 'SliccyProof-1').exists())
            self.assertTrue(any(row['step'] == 'staging-removal' and row['phase'] == 'completed' for row in self.rows))
        finally:
            os.close(fd)

    def test_existing_destination_is_not_reused_or_removed(self):
        library = self.home / 'library'
        existing = library / 'SliccyProof-1'
        existing.mkdir(parents=True)
        sentinel = existing / 'sentinel'
        sentinel.write_bytes(b'keep')
        fd = os.open(library, subject.DIR_FLAGS)
        try:
            with self.assertRaises(FileExistsError):
                subject.stage(fd, existing.name, self.expected, self.journal, time.monotonic() + 5)
            self.assertEqual(sentinel.read_bytes(), b'keep')
        finally:
            os.close(fd)

    def test_root_command_has_only_reviewed_program_fixed_host_env_and_canonical_run(self):
        args = adapter.arguments(Path('/fixed/system/python'), 'fixed reviewed program', 'stage', '123')
        self.assertEqual(args[0:2], ['/usr/bin/sudo', '-n'])
        self.assertEqual(args[-7:], ['-I', '-S', '-B', '-c', 'fixed reviewed program', 'stage', '123'])
        for run in ('0', '../1', '01', '1/2', '+1', '18446744073709551616'):
            with self.assertRaises(ValueError):
                adapter.arguments(Path('/fixed/system/python'), 'fixed reviewed program', 'stage', run)
        for action in ('grant', 'sign', 'launch'):
            with self.assertRaises(ValueError):
                adapter.arguments(Path('/fixed/system/python'), 'fixed reviewed program', action, '123')


if __name__ == '__main__':
    unittest.main()
