#pragma once
#include <stddef.h>
typedef int (*violin_run_command)(char *const [], char *, size_t, int);
int violin_restore_enforcing(const char *ksud, violin_run_command run);
