#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <endian.h>

#include "orc.h"

#define USAGE "%s elf-file [functions ...]\n"


/*
    orc_breakpoints

    outputs .gdbinit syntax to set breakpoints on the specified functions
*/

/*
    TODO:
    1. check if file is nonPIC
    2. if file is nonPIC,read .got.plt from MIPS_PLTGOT
    3. read .got from PLTGOT
    4. read MIPS_GOTSYM
    
    algorithm
    if (sym_index < MIPS_GOTSYM) {
        if (nonPIC and symbol reloc is R_MIPS_JUMP_SLOT) {
            .got_plt_index == reloc_index + 2
            x/xw got_plt_addr + got_plt_index
            break $__
            set $sym_name_bp = $bpnum
        }
        else {
            this is a dynamic symbol that is NOT GOT mapped (see Symbols section in MIPS-ABI.pdf)
            I honestly have no idea why this is a thing, the MIPS-ABI.pdf does not make it clear.
            break ($so_offset + sym_value)
        }
    }
    else {
        .got_index == (sym_index - MIPS_GOTSYM) + 2
        x/xw got_addr + got_index
        break $__
        set $sym_name_bp = $bpnum
    }
*/


int main(int argc, char *argv[])
{
    int ret;
    enum ORCError err;
    FILE *handle;
    Elf32_Ehdr elf_hdr;
    Elf32_Half ph_num, phdr_count;
    Elf32_Off ph_off;
    Elf32_Phdr *dyn_seg = NULL;
    Elf32_Dyn dynamic_tag;
    Elf32_Shdr dynsym_shdr;
    Elf32_Sym dyn_sym;
    Elf32_Word dyn_sym_idx;
    char *dynstr_table = NULL;

    if (argc < 3)
    {
        fprintf(stderr, USAGE, argv[0]);
        return 1;
    }

    if (!(handle = fopen(argv[1], "r+")))
    {
        fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    if (fread(&elf_hdr, sizeof(Elf32_Ehdr), 1, handle) != 1)
    {
        if (ferror(handle))
            fprintf(stderr, "Failed to read ELF header from %s\n", argv[1]);
        else
            fprintf(stderr, "No ELF header found in %s\n", argv[1]);

        goto err_exit;
    }

    if (!IS_SUPPORTED_ARCH((&elf_hdr))) {
        fprintf(stderr, "Currently only 32 bit big-endian MIPS binaries are supported\n");
        goto err_exit;
    }

    /* parse program header info */
    ph_num = be16toh(elf_hdr.e_phnum);
    ph_off = be32toh(elf_hdr.e_phoff);
    fprintf(stderr, "Found %hu program headers at offset %u\n", ph_num, ph_off);

    switch (find_program_headers(handle, ph_off, ph_num, PT_DYNAMIC, &dyn_seg, &phdr_count)) {
        case ORC_SUCCESS:
            break;
        default:
            goto err_exit;
    }

    switch ((err = find_dynamic_tag(handle, be32toh(dyn_seg->p_offset), be32toh(dyn_seg->p_filesz), DT_SYMTAB, &dynamic_tag))) {
        case ORC_SUCCESS:
            dynsym_shdr.sh_addr = be32toh(dynamic_tag.d_un.d_ptr);
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_SYMTAB dynamic tag\n");
        default:
            return err;
    }
    switch ((err = find_dynamic_tag(handle, be32toh(dyn_seg->p_offset), be32toh(dyn_seg->p_filesz), DT_SYMENT, &dynamic_tag))) {
        case ORC_SUCCESS:
            dynsym_shdr.sh_entsize = be32toh(dynamic_tag.d_un.d_val);
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_SYMENT dynamic tag\n");
        default:
            return err;
    }
    switch ((err = find_dynamic_tag(handle, be32toh(dyn_seg->p_offset), be32toh(dyn_seg->p_filesz), DT_MIPS_SYMTABNO, &dynamic_tag))) {
        case ORC_SUCCESS:
            dynsym_shdr.sh_size = be32toh(dynamic_tag.d_un.d_val) * dynsym_shdr.sh_entsize;
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_MIPS_SYMTABNO dynamic tag\n");
        default:
            return err;
    }

    if (read_dynstr_table(handle, dyn_seg, &dynstr_table) != ORC_SUCCESS) {
        fprintf(stderr, "Failed to read dynamic string table\n");
        goto err_exit;
    }

    for (int i = 2; i < argc; i++) {
        fprintf(stderr, "searching for symbol: %s...\n", argv[i]);
        switch ((err = find_dynamic_symbol(handle, argv[i], dynstr_table, &dynsym_shdr, &dyn_sym, &dyn_sym_idx)))
        {
        case ORC_SUCCESS:
            break;
        case ORC_SYM_NOT_FOUND:
            break;
        default:
            goto err_exit;
        }
    }
    goto cleanup;


err_exit:
    ret = 1;
cleanup:
    free(dynstr_table);
    free(dyn_seg);
    fclose(handle);
    return ret;
}