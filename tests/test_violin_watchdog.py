"""Exercise real fork/pipe watchdog paths using a private file, never SELinux."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class WatchdogTests(unittest.TestCase):
    def test_commit_eof_timeout_invalid_and_write_failure(self):
        code = r'''
#include "violin_watchdog.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
int main(void) {
    for (int scenario = 0; scenario < 5; scenario++) {
        char path[] = "/tmp/violin-watchdog-XXXXXX";
        int rollback = mkstemp(path), channel[2];
        assert(rollback >= 0 && write(rollback, "1", 1) == 1);
        assert(lseek(rollback, 0, SEEK_SET) == 0 && pipe(channel) == 0);
        pid_t child = fork(); assert(child >= 0);
        if (!child) {
            close(channel[1]);
            int rc = violin_watchdog(channel[0], scenario == 4 ? -1 : rollback, 30);
            _exit(rc == (scenario == 0 ? 0 : scenario == 4 ? -1 : 1) ? 0 : 1);
        }
        close(channel[0]);
        if (scenario == 0) assert(write(channel[1], "C", 1) == 1);
        if (scenario == 3) assert(write(channel[1], "X", 1) == 1);
        if (scenario != 2) close(channel[1]);
        int status;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        if (scenario == 2) close(channel[1]);
        char state = 0; assert(pread(rollback, &state, 1, 0) == 1);
        assert(state == (scenario == 0 || scenario == 4 ? '1' : '0'));
        close(rollback); unlink(path);
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder / 'test.c').write_text(code)
            exe = folder / 'test'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_GNU_SOURCE',
                            '-Wall', '-Wextra', '-Werror', '-I', str(ROOT / 'app/src/main/jni'),
                            str(folder / 'test.c'), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True, timeout=5)
