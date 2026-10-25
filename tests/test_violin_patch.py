"""Host-only ELF validation tests. Never loads a module or reads a real device."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

def fixture():
    data = bytearray(512)
    ident = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 1, 183, 1, 0, 0, 256, 0, 64, 0, 0, 64, 4, 1)
    names = b'\0.shstrtab\0.strtab\0.symtab\0'
    strings = b'\0prepare_creds\0'
    data[64:64+len(names)] = names
    data[96:96+len(strings)] = strings
    struct.pack_into('<IBBHQQ', data, 152, 1, 0x10, 0, 0, 0, 0)
    for index, values in enumerate([
        (0,0,0,0,0,0,0,0,0,0),
        (1,3,0,0,64,len(names),0,0,1,0),
        (11,3,0,0,96,len(strings),0,0,1,0),
        (19,2,0,0,128,48,2,1,8,24),
    ]):
        struct.pack_into('<IIQQQQIIQQ', data, 256+index*64, *values)
    return data

class PatcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.exe = Path(cls.work.name) / 'patch'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_GNU_SOURCE', '-DVIOLIN_PATCHER_CLI',
                        '-Wall', '-Wextra', '-Werror', str(ROOT/'app/src/main/jni/violin_patch.c'),
                        '-o', str(cls.exe)], check=True)
    @classmethod
    def tearDownClass(cls): cls.work.cleanup()
    def run_patch(self, data=None, symbol='ffff000000010000 T prepare_creds\n', good=True):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder/'in.ko').write_bytes(fixture() if data is None else data)
            filler = ''.join(f'ffff000000000000 T filler_{i}\n' for i in range(10001))
            (folder/'symbols').write_text(filler + symbol)
            proc = subprocess.run([str(self.exe), str(folder/'in.ko'), str(folder/'symbols'), str(folder/'out.ko')], capture_output=True)
            self.assertEqual(proc.returncode == 0, good, proc.stderr.decode())
            if not good:
                self.assertFalse((folder/'out.ko').exists())
                return
            return (folder/'out.ko').read_bytes()
    def test_patches_only_index_and_value(self):
        result = self.run_patch()
        expected = fixture()
        struct.pack_into('<H', expected, 158, 0xfff1)
        struct.pack_into('<Q', expected, 160, 0xffff000000010000)
        self.assertEqual(result, expected)
    def test_missing(self): self.run_patch(symbol='', good=False)
    def test_zero(self): self.run_patch(symbol='0000000000000000 T prepare_creds\n', good=False)
    def test_conflict(self): self.run_patch(symbol='ffff000000010000 T prepare_creds\nffff000000010008 T prepare_creds\n', good=False)
    def test_same_address_duplicate(self): self.run_patch(symbol='ffff000000010000 T prepare_creds\n' * 2)
    def test_module_symbol_rejected(self): self.run_patch(symbol='ffff000000010000 T prepare_creds [other]\n', good=False)
    def test_truncated(self): self.run_patch(data=fixture()[:280], good=False)
    def test_wrong_machine(self):
        data = fixture(); struct.pack_into('<H', data, 18, 62)
        self.run_patch(data=data, good=False)
    def test_bad_string_index(self):
        data = fixture(); struct.pack_into('<I', data, 152, 999)
        self.run_patch(data=data, good=False)
    def test_section_overflow(self):
        data = fixture(); struct.pack_into('<Q', data, 256+3*64+24, 2**64-16)
        self.run_patch(data=data, good=False)

if __name__ == '__main__': unittest.main()
