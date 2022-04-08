#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <stdint.h>
#include <elf.h>
#include <endian.h>

#define USAGE "%s elf-file\n"
/*
    TODO:
        handle 64 bit
        handle little endian
*/

/*
    Program Headers
    INTERP  .interp FileSiz
    DYNAMIC .dynamic    FileSiz

    dynamic section entries
    STRTAB  .dynstr STRSZ
    SYMTAB  .dynsym (MIPS_SYMTABNO * SYMENT)
    REL .rel.dyn    RELSZ
    JMPREL  .rel.plt    PTLRELSZ
    MIPS_PLTGOT .got.plt    (((PLTRELSZ/RELENT) + 2) * sizeof(address))
    PLTGOT  .got    ((MIPS_SYMTABNO - MIPS_GOTSYM) + MIPS_LOCAL_GOTNO) * sizeof(address)

    INIT    .init
    FINI    .fini

    REGINFO .region Elf32_RegInfo
*/

struct section_info {
   Elf32_Shdr *headers;
   Elf32_Half num_headers;

   uint8_t *shstrtab;
   size_t shstrtab_len;
};

enum ORCError {
    ORC_SUCCESS,
    ORC_CRITICIAL,
    ORC_FILE_IO_ERR,
    ORC_INVALID_ELF,
    ORC_DYN_TAG_NOT_FOUND,
    ORC_DYN_VALUE_INVALID
};

enum ORCError add_section_header(struct section_info *s_info, const char *name, Elf32_Shdr *sh);
enum ORCError find_dynamic_tag(FILE *handle, Elf32_Off dyn_seg_offset, Elf32_Word dyn_seg_size, Elf32_Sword tag, Elf32_Dyn *dynamic_tag);
enum ORCError parse_dynamic_segment(FILE *handle, Elf32_Phdr *dyn_seg, struct section_info *s_info);
enum ORCError count_mips_jump_slot_relocs(FILE *handle, Elf32_Off rel_plt_offset, Elf32_Word rel_plt_size, Elf32_Word *count);


int main(int argc, char *argv[])
{
    FILE *handle;
    Elf32_Ehdr elf_header;
    Elf32_Phdr program_header;
    Elf32_Shdr null_section = { 0 };
    long file_size, shstrtab_offset = 0, sh_offset = 0;
    int ret;
    enum ORCError err;
    struct section_info s_info = { 0 };

    if (argc < 2)
    {
        fprintf(stderr, USAGE, argv[0]);
        return 1;
    }

    if (!(handle = fopen(argv[1], "r+")))
    {
        fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    if (fread(&elf_header, sizeof(Elf32_Ehdr), 1, handle) != 1)
    {
        if (ferror(handle))
            fprintf(stderr, "Failed to read ELF header from %s\n", argv[1]);
        else
            fprintf(stderr, "No ELF header found in %s\n", argv[1]);

        fclose(handle);
        return 1;
    }

    if (elf_header.e_shoff || elf_header.e_shnum) {
        fprintf(stderr, "%s already contains %hu section headers at offset 0x%x\n", argv[1], be16toh(elf_header.e_shnum), be32toh(elf_header.e_shoff));
        goto err_exit;
    }

    /* parse program header info */
    Elf32_Half ph_num = be16toh(elf_header.e_phnum), ph_size = be16toh(elf_header.e_phentsize);
    Elf32_Off ph_off = be32toh(elf_header.e_phoff);
    fprintf(stderr, "Found %hu program headers of size %hu at offset %u\n", ph_num, ph_size, ph_off);

    if (fseek(handle, ph_off, SEEK_SET) == -1)
    {
        fprintf(stderr, "Failed to seek to program headers at offset 0x%x in %s: %s\n", ph_off, argv[1], strerror(errno));
        fclose(handle);
        return 1;
    }

    if (add_section_header(&s_info, "", &null_section) != ORC_SUCCESS)
       goto err_exit;

    /* get dynamic segment */
    for (Elf32_Half i = 0; i < ph_num; i++)
    {
        if (fread(&program_header, sizeof(Elf32_Phdr), 1, handle) != 1)
        {
            if (ferror(handle))
                fprintf(stderr, "Failed to read program header %hu from %s\n", i, argv[1]);
            else
                fprintf(stderr, "Invalid program headers found in %s\n", argv[1]);

            fclose(handle);
            return 1;
        }

        if (be32toh(program_header.p_type) == PT_DYNAMIC) {
            if ((err = parse_dynamic_segment(handle, &program_header, &s_info)) == ORC_CRITICIAL)
                goto err_exit;
            break;
        }
    }

    if (fseek(handle, 0L, SEEK_END) == -1 || (file_size = ftell(handle)) == -1)
    {
        fprintf(stderr, "Failed to obtain file size of %s: %s\n", argv[1], strerror(errno));
        fclose(handle);
        return 1;
    }
    fprintf(stderr, "File %s size: %li bytes\n", argv[1], file_size);

    if (file_size % 32)
    {
        shstrtab_offset = 32 - (file_size % 32);
        if (fseek(handle, shstrtab_offset, SEEK_CUR) == -1)
        {
            fprintf(stderr, "Failed to seek to .shstrtab offset at %li in %s: %s\n", file_size + shstrtab_offset, argv[1], strerror(errno));
            fclose(handle);
            return 1;
        }
    }
    fprintf(stderr, ".shstrtab offset: %li\n", file_size + shstrtab_offset);

    /*
    .shstrtab
    */
    Elf32_Shdr shstrtab_header = {0};
    shstrtab_header.sh_name = htobe32(s_info.num_headers - 1);
    shstrtab_header.sh_type = htobe32(SHT_STRTAB);
    shstrtab_header.sh_offset = htobe32(file_size + shstrtab_offset);
    shstrtab_header.sh_size = htobe32(s_info.shstrtab_len + strlen(".shstrtab") + 1); /* plus terminating \0 */
    shstrtab_header.sh_addralign = htobe32(1);

    if (add_section_header(&s_info, ".shstrtab", &shstrtab_header))
        goto err_exit;


    if (fwrite(s_info.shstrtab, s_info.shstrtab_len, 1, handle) != 1)
    {
        fprintf(stderr, "Failed to write %lu byte .shstrtab to %s at offset %li\n", s_info.shstrtab_len, argv[1], file_size + shstrtab_offset);
        fclose(handle);
        return 1;
    }
    fprintf(stderr, "Wrote %lu byte .shstrtab to %s at offset %li\n", s_info.shstrtab_len, argv[1], file_size + shstrtab_offset);

    if (s_info.shstrtab_len % 4)
    {
        sh_offset = 4 - (s_info.shstrtab_len % 4);
        if (fseek(handle, sh_offset, SEEK_CUR) == -1)
        {
            fprintf(
                stderr,
                "Failed to seek to section header offset at %lu in %s: %s\n",
                file_size + shstrtab_offset + s_info.shstrtab_len + sh_offset,
                argv[1],
                strerror(errno)
            );
            fclose(handle);
            return 1;
        }
    }
    fprintf(stderr, "section header offset: %li\n", file_size + shstrtab_offset + s_info.shstrtab_len + sh_offset);
    fprintf(stderr, "%li\n", ftell(handle));

    if (fwrite(s_info.headers, sizeof(Elf32_Shdr), s_info.num_headers, handle) != s_info.num_headers) {
        fprintf(stderr, "Failed to write %hu section headers to %s\n", s_info.num_headers, argv[1]);
        fclose(handle);
        return 1;
    }

    elf_header.e_shentsize = htobe16(sizeof(Elf32_Shdr));
    elf_header.e_shnum = htobe16(s_info.num_headers);
    elf_header.e_shoff = htobe32(file_size + shstrtab_offset + s_info.shstrtab_len + sh_offset);
    elf_header.e_shstrndx = htobe16(s_info.num_headers - 1);

    if (fseek(handle, 0, SEEK_SET) == -1) {
        fprintf(stderr, "Failed to seek to beginning of %s: %s\n", argv[1], strerror(errno));
        fclose(handle);
        return 1;
    }

    if (fwrite(&elf_header, sizeof(Elf32_Ehdr), 1, handle) != 1) {
        fprintf(stderr, "Failed to write updated ELF header to %s\n", argv[1]);
        fclose(handle);
        return 1;
    }

    ret = 0;
    goto cleanup;

err_exit:
    ret = 1;

cleanup:
    free(s_info.headers);
    free(s_info.shstrtab);
    fclose(handle);
    return ret;
}

enum ORCError add_section_header(struct section_info *s_info, const char *name, Elf32_Shdr *sh) {
    size_t name_len;

    name_len = strlen(name) + 1; /* plus terminating \0 */
    if (!(s_info->shstrtab = reallocarray(s_info->shstrtab, s_info->shstrtab_len + name_len, sizeof(uint8_t)))) {
        fprintf(stderr, "Failed to allocate %lu bytes of additional space to add %s to .shstrtab: %s\n", name_len, name, strerror(errno));
        return ORC_CRITICIAL;
    }
    strcpy(s_info->shstrtab + s_info->shstrtab_len, name);
    sh->sh_name = htobe32(s_info->shstrtab_len);
    s_info->shstrtab_len += name_len;

    if (!(s_info->headers = reallocarray(s_info->headers, s_info->num_headers + 1, sizeof(Elf32_Shdr)))) {
        fprintf(stderr, "Failed to allocate space for %s section header: %s\n", name, strerror(errno));
        return ORC_CRITICIAL;
    }
    memcpy(s_info->headers + s_info->num_headers, sh, sizeof(Elf32_Shdr));
    s_info->num_headers++;

    fprintf(
        stderr,
        "Added section header: %u\t%s\t%u\t0x%x\t0x%x\t0x%x\t0x%x\t%u\t%u\t%u\t%u\n",
        be32toh(sh->sh_name),
        name,
        be32toh(sh->sh_type),
        be32toh(sh->sh_addr),
        be32toh(sh->sh_offset),
        be32toh(sh->sh_size),
        be32toh(sh->sh_entsize),
        be32toh(sh->sh_flags),
        be32toh(sh->sh_link),
        be32toh(sh->sh_info),
        be32toh(sh->sh_addralign)
    );
    return ORC_SUCCESS;
}


enum ORCError parse_dynamic_segment(FILE *handle, Elf32_Phdr *dyn_seg, struct section_info *s_info) {
    /*
        TODO: and subroutines and better error handling to account
        for various architectures and dynamic tag combinations
    */
   /*
    TODO: fill in missing sht_addralign
   */
    enum ORCError err;
    Elf32_Shdr dynamic = { 0 }, dynstr = { 0 }, dynsym = { 0 }, rel_plt = { 0 }, got_plt = { 0 };
    Elf32_Dyn dynamic_tag;
    Elf32_Addr base_addr;
    Elf32_Off dyn_seg_offset = be32toh(dyn_seg->p_offset);
    Elf32_Word dyn_seg_size = be32toh(dyn_seg->p_filesz), syment, symtabno, pltrel, dynstr_idx, got_plt_idx, dynsym_idx;

    /*
        TODO
        only for MIPS
        x64 binaries don't have a base address
    */
    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_MIPS_BASE_ADDRESS, &dynamic_tag))) {
        case ORC_SUCCESS:
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find MIPS_BASE_ADDRESS dynamic tag\n");
        default:
            return err;
    }
    base_addr = be32toh(dynamic_tag.d_un.d_ptr);
    fprintf(stderr, "Found MIPS base address at 0x%x\n", base_addr);


    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_STRTAB, &dynamic_tag))) {
        case ORC_SUCCESS:
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_STRTAB dynamic tag\n");
        default:
            return err;
    }
    dynstr.sh_addr = dynamic_tag.d_un.d_ptr;
    fprintf(stderr, "Found DT_STRTAB at 0x%x\n", be32toh(dynstr.sh_addr));

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_STRSZ, &dynamic_tag))) {
        case ORC_SUCCESS:
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_STRSZ dynamic tag\n");
        default:
            return err;
    }
    dynstr.sh_size = dynamic_tag.d_un.d_val;
    fprintf(stderr, "Found DT_STRSZ at %u\n", be32toh(dynstr.sh_size));

    dynstr.sh_offset = htobe32(be32toh(dynstr.sh_addr) - base_addr);
    dynstr.sh_addralign = htobe32(1);
    dynstr.sh_type = htobe32(SHT_STRTAB);
    dynstr.sh_flags = htobe32(SHF_ALLOC);

    dynstr_idx = s_info->num_headers;
    if ((err = add_section_header(s_info, ".dynstr", &dynstr)) != ORC_SUCCESS)
        return err;

    dynamic.sh_addr = dyn_seg->p_vaddr;
    dynamic.sh_addralign = dyn_seg->p_align;
    dynamic.sh_entsize = htobe32(sizeof(Elf32_Dyn));
    if (dyn_seg->p_flags & htobe32(PF_R))
        dynamic.sh_flags |= htobe32(SHF_ALLOC);
    if (dyn_seg->p_flags & htobe32(PF_W))
        dynamic.sh_flags |= htobe32(SHF_WRITE);
    if (dyn_seg->p_flags & htobe32(PF_X))
        dynamic.sh_flags |= htobe32(SHF_EXECINSTR);
    dynamic.sh_link = htobe32(dynstr_idx);
    dynamic.sh_offset = dyn_seg->p_offset;
    dynamic.sh_size = dyn_seg->p_filesz; /* Practical Binary Analysis, 2.4.3 */
    dynamic.sh_type = htobe32(SHT_DYNAMIC);

    if ((err = add_section_header(s_info, ".dynamic", &dynamic)) != ORC_SUCCESS)
        return err;

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_SYMTAB, &dynamic_tag))) {
        case ORC_SUCCESS:
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_SYMTAB dynamic tag\n");
        default:
            return err;
    }
    dynsym.sh_addr = dynamic_tag.d_un.d_ptr;
    fprintf(stderr, "Found DT_SYMTAB at 0x%x\n", be32toh(dynsym.sh_addr));

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_SYMENT, &dynamic_tag))) {
        case ORC_SUCCESS:
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_SYMENT dynamic tag\n");
        default:
            return err;
    }
    syment = be32toh(dynamic_tag.d_un.d_val);
    fprintf(stderr, "Found DT_SYMENT at 0x%x\n", syment);

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_MIPS_SYMTABNO, &dynamic_tag))) {
        case ORC_SUCCESS:
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_MIPS_SYMTABNO dynamic tag\n");
        default:
            return err;
    }
    symtabno = be32toh(dynamic_tag.d_un.d_val);
    fprintf(stderr, "Found DT_MIPS_SYMTABNO at 0x%x\n", symtabno);

    dynsym.sh_offset = htobe32(be32toh(dynsym.sh_addr) - base_addr);
    dynsym.sh_type = htobe32(SHT_DYNSYM);
    dynsym.sh_flags = htobe32(SHF_ALLOC);
    dynsym.sh_size = htobe32(syment * symtabno);
    dynsym.sh_entsize = htobe32(syment);
    dynsym.sh_link = htobe32(dynstr_idx);
    /*
        One greater than the symbol table index of the last local symbol. 
        https://docs.oracle.com/cd/E19455-01/806-3773/6jct9o0bs/index.html#elf-15226
        since this is the dynamic string table, this will always be 1
    */
    dynsym.sh_info = htobe32(1);

    dynsym_idx = s_info->num_headers;
    if ((err = add_section_header(s_info, ".dynsym", &dynsym)) != ORC_SUCCESS)
        return err;

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_MIPS_PLTGOT, &dynamic_tag))) {
        case ORC_SUCCESS:
            got_plt.sh_addr = dynamic_tag.d_un.d_ptr;
            fprintf(stderr, "Found DT_MIPS_PLTGOT: 0x%x\n", be32toh(got_plt.sh_addr));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_MIPS_PLTGOT dynamic tag\n");
            switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_MIPS_RWPLT, &dynamic_tag))) {
                case ORC_SUCCESS:
                    got_plt.sh_addr = dynamic_tag.d_un.d_ptr;
                    fprintf(stderr, "Found DT_MIPS_RWPLT: 0x%x\n", be32toh(got_plt.sh_addr));
                    break;
                case ORC_DYN_TAG_NOT_FOUND:
                    fprintf(stderr, "Failed to find DT_MIPS_RWPLT dynamic tag\n");
                    
                default:
                    return err;
            }
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_PLTREL, &dynamic_tag))) {
        case ORC_SUCCESS:
            pltrel = dynamic_tag.d_un.d_val;
            /* 
                TODO:
                Add support for other architectures which may support
                DT_RELA relocations - but MIPS expects DT_REL
            */
            if (be32toh(pltrel) != DT_REL) { /*  && be32toh(pltrel) != DT_RELA */
                fprintf(stderr, "DT_PLTREL has invalid value: %u\n", be32toh(pltrel));
                return ORC_DYN_VALUE_INVALID;
            }
            fprintf(stderr, "DT_PLTREL == DT_REL: %u\n", be32toh(pltrel) == DT_REL);
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_PLTREL dynamic tag\n");
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_RELENT, &dynamic_tag))) {
        case ORC_SUCCESS:
            rel_plt.sh_entsize = dynamic_tag.d_un.d_val;
            fprintf(stderr, "Found DT_RELENT: %u\n", be32toh(rel_plt.sh_entsize));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_RELENT dynamic tag\n");
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_JMPREL, &dynamic_tag))) {
        case ORC_SUCCESS:
            rel_plt.sh_addr = dynamic_tag.d_un.d_ptr;
            fprintf(stderr, "Found DT_JMPREL: 0x%x\n", be32toh(rel_plt.sh_addr));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_JMPREL dynamic tag\n");
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_PLTRELSZ, &dynamic_tag))) {
        case ORC_SUCCESS:
            rel_plt.sh_size = dynamic_tag.d_un.d_val;
            fprintf(stderr, "Found DT_PLTRELSZ: %u\n", be32toh(rel_plt.sh_size));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_PLTRELSZ dynamic tag\n");
        default:
            return err;
    }

    rel_plt.sh_offset = htobe32(be32toh(rel_plt.sh_addr) - base_addr);
    rel_plt.sh_type = htobe32(SHT_REL);
    /*
        This section headers sh_info field holds a section header table index.
        https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-94076.html
    */
    rel_plt.sh_flags = htobe32(SHF_ALLOC) | htobe32(SHF_INFO_LINK);
    rel_plt.sh_link = htobe32(dynsym_idx);

    Elf32_Word num_jump_slot_relocs;
    if ((err = count_mips_jump_slot_relocs(handle, be32toh(rel_plt.sh_offset), be32toh(rel_plt.sh_size), &num_jump_slot_relocs)) != ORC_SUCCESS)
        return err;

    /* 
        number of R_MIPS_JUMP_SLOT in .rel.plt + pltgot[0] (dynamic linker's PLT resolver) + pltgot[1] (object link map)
        multiplied by the size of a MIPS32 address (4 bytes)

    */
    got_plt.sh_size = htobe32((num_jump_slot_relocs + 2) * 4);
    got_plt.sh_offset = htobe32(be32toh(got_plt.sh_addr) - base_addr - 0x10000); /* TODO: calculate dynamically */
    got_plt.sh_type = htobe32(SHT_PROGBITS);
    got_plt.sh_flags = htobe32(SHF_ALLOC) | htobe32(SHF_WRITE) | htobe32(SHF_MIPS_GPREL);
    got_plt.sh_entsize = htobe32(4); /* based on architecture address length */

    got_plt_idx = s_info->num_headers;
    if ((err = add_section_header(s_info, ".got.plt", &got_plt)) != ORC_SUCCESS)
        return err;

    rel_plt.sh_info = htobe32(got_plt_idx);
    if ((err = add_section_header(s_info, ".rel.plt", &rel_plt)) != ORC_SUCCESS)
        return err;

    return ORC_SUCCESS;
}


enum ORCError find_dynamic_tag(FILE *handle, Elf32_Off dyn_seg_offset, Elf32_Word dyn_seg_size, Elf32_Sword tag, Elf32_Dyn *dynamic_tag) {
   if (fseek(handle, dyn_seg_offset, SEEK_SET) == -1) {
       fprintf(stderr, "Failed to seek to DYNAMIC segment at offset %u: %s\n", dyn_seg_offset, strerror(errno));
       return ORC_CRITICIAL;
   }
    for (Elf32_Word i = 0; i < dyn_seg_size; i += sizeof(Elf32_Dyn)) {
        if (fread(dynamic_tag, sizeof(Elf32_Dyn), 1, handle) != 1)
        {
            if (ferror(handle)) {
                fprintf(stderr, "Failed to read dynamic tag %hu\n", i);
                return ORC_FILE_IO_ERR;
            }
            fprintf(stderr, "Invalid dynamic tags\n");
            return ORC_INVALID_ELF;
        }

        dynamic_tag->d_tag = be32toh(dynamic_tag->d_tag);
        if (dynamic_tag->d_tag == tag)
            return ORC_SUCCESS;
    }
    fprintf(stderr, "Dynamic tag %u not found\n", tag);
    return ORC_DYN_TAG_NOT_FOUND;

}

enum ORCError count_mips_jump_slot_relocs(FILE *handle, Elf32_Off rel_plt_offset, Elf32_Word rel_plt_size, Elf32_Word *count) {
    Elf32_Rel rel;
    if (fseek(handle, rel_plt_offset, SEEK_SET) == -1) {
        fprintf(stderr, "Failed to seek to .rel.plt section at offset %u: %s\n", rel_plt_offset, strerror(errno));
        return ORC_CRITICIAL;
    }
    fprintf(stderr, "Reading relocation in .rel.plt at offset 0x%x\n", rel_plt_offset);

    *count = 0;
    for (Elf32_Word i = 0; i < rel_plt_size; i += sizeof(Elf32_Rel)) {
        if (fread(&rel, sizeof(Elf32_Rel), 1, handle) != 1) {
            if (ferror(handle)) {
                fprintf(stderr, "Failed to read .rel.plt relocation %u\n", i/4);
                return ORC_FILE_IO_ERR;
            }
            fprintf(stderr, "Invalid .rel.plt section\n");
            return ORC_INVALID_ELF;
        }

        if (ELF32_R_TYPE(be32toh(rel.r_info)) == R_MIPS_JUMP_SLOT)
            *count += 1;
    }

    fprintf(stderr, "Found %u MIPS_JUMP_SLOT relocations in .rel.plt at 0x%x\n", *count, rel_plt_offset);
    return ORC_SUCCESS;
}