"""Exercise the actual command runner with inherited FDs and real child processes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CommandTests(unittest.TestCase):
    def test_stdio_isolation_exit_status_output_drain_and_timeout(self):
        code = r'''
#include "violin.c"
#include <assert.h>
/* These device-only entry points are never called by this host test. */
int violin_patch_module(const char *a, const char *b, const char *c) {
    (void)a; (void)b; (void)c; abort();
}
int violin_restore_enforcing(const char *ksud, violin_run_command run) {
    (void)ksud; (void)run; abort();
}
int main(void) {
    int input[2]; assert(pipe(input) == 0);
    assert(write(input[1], "parent input\n", 13) == 13);
    assert(dup2(input[0], STDIN_FILENO) == STDIN_FILENO); close(input[0]);
    char path[] = "/tmp/violin-command-XXXXXX";
    int inherited = mkstemp(path); assert(inherited >= 0); unlink(path);
    assert(dup2(inherited, STDERR_FILENO) == STDERR_FILENO);
    char output[64];
    int rc = command((char *[]){"/bin/sh", "-c",
        "if read -r line; then printf BAD_STDIN; fi; printf OUT; printf ERR >&2; exit 7", NULL},
        output, sizeof(output), 2);
    assert(rc == 7 && !strcmp(output, "OUTERR"));
    assert(lseek(inherited, 0, SEEK_END) == 0); /* stderr never reached the old log FD */
    char original[13]; assert(read(STDIN_FILENO, original, sizeof(original)) == 13);
    assert(!memcmp(original, "parent input\n", 13)); close(input[1]);
    rc = command((char *[]){"/bin/sh", "-c",
        "i=0; while [ $i -lt 6000 ]; do printf x; printf y >&2; i=$((i+1)); done", NULL},
        output, sizeof(output), 5);
    assert(rc == 0 && strlen(output) == sizeof(output) - 1);
    rc = command((char *[]){"/bin/sh", "-c", "sleep 30 & wait", NULL}, output, sizeof(output), 1);
    assert(rc == -1);
    close(inherited); return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder / 'test.c').write_text(code)
            exe = folder / 'test'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_GNU_SOURCE',
                            '-Wall', '-Wextra', '-Werror', '-I', str(ROOT / 'app/src/main/jni'),
                            str(folder / 'test.c'), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True, timeout=12)
