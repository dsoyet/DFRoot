#pragma once
/* Does not load a module. Rejects missing, zero and ambiguous symbols. */
int violin_patch_module(const char *input, const char *kallsyms, const char *output);
