#include "violin_patch.h"
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct symbol { char *name; uint64_t address; };
static int compare(const void *a, const void *b) {
    return strcmp(((const struct symbol *)a)->name, ((const struct symbol *)b)->name);
}
static int range(size_t total, uint64_t offset, uint64_t length) {
    return offset <= total && length <= total - offset;
}
static const char *name_at(const unsigned char *data, size_t length, uint32_t offset) {
    return offset < length && memchr(data + offset, 0, length - offset)
        ? (const char *)data + offset : NULL;
}
int violin_patch_module(const char *input, const char *kallsyms, const char *output) {
    FILE *file = NULL;
    unsigned char *data = NULL;
    struct symbol *symbols = NULL;
    size_t count = 0, capacity = 0, patched = 0;
    int result = -1;
    file = fopen(kallsyms, "r");
    if (!file) goto done;
    char line[2048], name[1024], type, module[256];
    unsigned long long address;
    while (fgets(line, sizeof(line), file)) {
        /* Only resolve built-in, exact names. Do not guess compiler suffixes. */
        if (sscanf(line, "%llx %c %1023s %255s", &address, &type, name, module) != 3)
            continue;
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 16384;
            void *p = realloc(symbols, next * sizeof(*symbols));
            if (!p) goto done;
            symbols = p; capacity = next;
        }
        symbols[count].name = strdup(name);
        if (!symbols[count].name) goto done;
        symbols[count++].address = address;
    }
    if (ferror(file) || count < 10000) goto done;
    fclose(file); file = NULL;
    qsort(symbols, count, sizeof(*symbols), compare);
    file = fopen(input, "rb");
    if (!file || fseek(file, 0, SEEK_END)) goto done;
    long size = ftell(file);
    if (size < (long)sizeof(Elf64_Ehdr) || size > 16 * 1024 * 1024) goto done;
    rewind(file);
    data = malloc((size_t)size);
    if (!data || fread(data, 1, size, file) != (size_t)size) goto done;
    fclose(file); file = NULL;
    Elf64_Ehdr header;
    memcpy(&header, data, sizeof(header));
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) || header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_ident[EI_VERSION] != EV_CURRENT ||
        header.e_machine != EM_AARCH64 || header.e_type != ET_REL || header.e_version != EV_CURRENT ||
        header.e_ehsize != sizeof(header) || header.e_shentsize != sizeof(Elf64_Shdr) ||
        !header.e_shnum || header.e_shstrndx >= header.e_shnum ||
        !range(size, header.e_shoff, (uint64_t)header.e_shnum * sizeof(Elf64_Shdr))) goto done;
    Elf64_Shdr symtab = {0}, strings = {0};
    int found = 0;
    for (unsigned i = 0; i < header.e_shnum; i++) {
        Elf64_Shdr section;
        memcpy(&section, data + header.e_shoff + i * sizeof(section), sizeof(section));
        if (section.sh_type != SHT_NOBITS && !range(size, section.sh_offset, section.sh_size)) goto done;
        if (section.sh_type == SHT_SYMTAB) { symtab = section; found++; }
    }
    if (found != 1 || symtab.sh_link >= header.e_shnum || symtab.sh_entsize != sizeof(Elf64_Sym) ||
        !symtab.sh_size || symtab.sh_size % sizeof(Elf64_Sym)) goto done;
    memcpy(&strings, data + header.e_shoff + symtab.sh_link * sizeof(strings), sizeof(strings));
    if (strings.sh_type != SHT_STRTAB || !range(size, strings.sh_offset, strings.sh_size)) goto done;
    for (size_t i = 1; i < symtab.sh_size / sizeof(Elf64_Sym); i++) {
        Elf64_Sym sym;
        size_t off = symtab.sh_offset + i * sizeof(sym);
        memcpy(&sym, data + off, sizeof(sym));
        const char *symbol_name = name_at(data + strings.sh_offset, strings.sh_size, sym.st_name);
        if (!symbol_name) goto done;
        if (sym.st_shndx != SHN_UNDEF || !*symbol_name) continue;
        struct symbol key = { .name = (char *)symbol_name };
        struct symbol *entry = bsearch(&key, symbols, count, sizeof(*symbols), compare);
        if (!entry) { fprintf(stderr, "missing symbol: %s\n", symbol_name); goto done; }
        size_t index = entry - symbols;
        while (index && !strcmp(symbols[index - 1].name, symbol_name)) index--;
        uint64_t value = symbols[index].address;
        if (value < UINT64_C(0xffff000000000000)) {
            fprintf(stderr, "zero/non-kernel symbol: %s\n", symbol_name); goto done;
        }
        for (size_t j = index + 1; j < count && !strcmp(symbols[j].name, symbol_name); j++) {
            if (symbols[j].address != value) {
                fprintf(stderr, "conflicting symbol: %s\n", symbol_name); goto done;
            }
        }
        sym.st_shndx = SHN_ABS; sym.st_value = value;
        memcpy(data + off, &sym, sizeof(sym)); patched++;
        printf("patch %s -> %016llx\n", symbol_name, (unsigned long long)value);
    }
    if (!patched) goto done;
    /* No output is created until every import has been resolved. */
    file = fopen(output, "wb");
    if (!file) goto done;
    if (fwrite(data, 1, size, file) != (size_t)size) { fclose(file); file = NULL; remove(output); goto done; }
    int closed = fclose(file); file = NULL;
    if (closed) { remove(output); goto done; }
    printf("validated ELF64 AArch64: %zu symbols patched\n", patched);
    result = 0;
done:
    if (file) fclose(file);
    for (size_t i = 0; i < count; i++) free(symbols[i].name);
    free(symbols); free(data);
    if (result) fprintf(stderr, "module validation/patching failed; no load allowed\n");
    return result;
}
#ifdef VIOLIN_PATCHER_CLI
int main(int argc, char **argv) {
    return argc == 4 && violin_patch_module(argv[1], argv[2], argv[3]) == 0 ? 0 : 1;
}
#endif
