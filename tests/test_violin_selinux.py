"""Host-only tests for rejecting stale/partial SELinux status-page snapshots."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class SelinuxStatusTests(unittest.TestCase):
    def test_status_and_domain_decisions(self):
        source = r'''
#include "violin_selinux.h"
#include <assert.h>
int main(void) {
    struct violin_selinux_status s = {1, 2, 0, 0, 1};
    assert(sizeof(s) == 20);
    assert(violin_status_valid(&s, sizeof(s)));
    s.sequence = 0; assert(violin_status_valid(&s, sizeof(s)));
    s.enforcing = 1; assert(!violin_status_valid(&s, sizeof(s)));
    s.enforcing = 0; s.sequence = 3;
    assert(!violin_status_valid(&s, sizeof(s)));
    s.sequence = 4; s.version = 2;
    assert(!violin_status_valid(&s, sizeof(s)));
    s.version = 1; s.deny_unknown = 2;
    assert(!violin_status_valid(&s, sizeof(s)));
    s.deny_unknown = 1;
    assert(!violin_status_valid(&s, sizeof(s) - 1));
    assert(!violin_status_valid(&s, sizeof(s) + 1));
    assert(!violin_su_permissive(0));
    assert(!violin_su_permissive(2));
    assert(violin_su_permissive(1));
    assert(violin_su_permissive(3));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder / 'test.c').write_text(source)
            exe = folder / 'test'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I', str(ROOT / 'app/src/main/jni'), str(folder / 'test.c'),
                            '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)
