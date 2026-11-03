import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('manifest', Path(__file__).resolve().parents[2] / 'script/universal_manifest.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    data = bytearray(1024)
    struct.pack_into('>II', data, 0, 0xCAFEBABE, 2)
    for index, (cpu, sub, offset) in enumerate([(0x0100000c, 0, 256), (0x01000007, 3, 512)]):
        struct.pack_into('>IIIII', data, 8 + index * 20, cpu, sub, offset, 256, 8)
        struct.pack_into('<IIIIIIII', data, offset, 0xFEEDFACF, cpu, sub, 2, 1, 16, 0, 0)
        struct.pack_into('<IIII', data, offset + 32, 0x1D, 16, 128, 64)
    return data


class FatMappingTests(unittest.TestCase):
    def test_exact_two_architecture_ranges(self):
        result = module.slices(fixture())
        self.assertEqual([(r['architecture'], r['offset']) for r in result], [('arm64', 256), ('x86_64', 512)])

    def test_duplicate_overlap_truncation_and_wrong_cpu_refused(self):
        for byte_offset, value in [(4, 1), (28, 0x0100000c), (36, 256), (40, 0xFFFFFFFF)]:
            data = fixture()
            struct.pack_into('>I', data, byte_offset, value)
            with self.assertRaises(ValueError): module.slices(data)
        with self.assertRaises(ValueError): module.slices(fixture()[:600])
        data = fixture(); struct.pack_into('<I', data, 260, 0x01000007)
        with self.assertRaises(ValueError): module.slices(data)

    def test_signature_must_be_unique_and_in_slice(self):
        data = fixture(); struct.pack_into('<I', data, 296, 255)
        with self.assertRaises(ValueError): module.slices(data)
        data = fixture(); struct.pack_into('<I', data, 288, 0)
        with self.assertRaises(ValueError): module.slices(data)
