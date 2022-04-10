#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <stdint.h>
#include <elf.h>
#include <endian.h>

#define USAGE "%s elf-file\n"
#define SHT_MIPS_ABIFLAGS 0x7000002a /* This is not included in elf.h */
/*
    TODO:
        handle 64 bit
        handle little endian
*/

/*
    Program Headers

            .MIPS.stubs

    dynamic section entries

    DT_MIPS_RLD_MAP .rld_map

    musl-gcc -fno-PIC -mips16 hello_world.c -mno-abicalls -L/mnt/unifi/lib/ -o hello_world16e_nopic
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
    ORC_DYN_VALUE_INVALID,
    ORC_PHDR_NOT_FOUND
};

enum ORCError add_section_header(struct section_info *s_info, const char *name, Elf32_Shdr *sh);
enum ORCError find_dynamic_tag(FILE *handle, Elf32_Off dyn_seg_offset, Elf32_Word dyn_seg_size, Elf32_Sword tag, Elf32_Dyn *dynamic_tag);
enum ORCError parse_dynamic_segment(FILE *handle, Elf32_Phdr *dyn_seg, Elf32_Phdr *loadable_segs, Elf32_Half num_loadable_segs, struct section_info *s_info);
enum ORCError count_mips_jump_slot_relocs(FILE *handle, Elf32_Off rel_plt_offset, Elf32_Word rel_plt_size, Elf32_Word *count);
enum ORCError find_program_headers(FILE *handle, Elf32_Off ph_off, Elf32_Half ph_num, Elf32_Word seg_type, Elf32_Phdr **phdrs, Elf32_Half *count);
enum ORCError calculate_file_offset(Elf32_Phdr *loadable_segs, Elf32_Half num_segs, Elf32_Addr base_addr, Elf32_Addr vaddr, Elf32_Off *file_off);
enum ORCError parse_mips_nonpic(
    FILE *handle,
    Elf32_Off dyn_seg_offset,
    Elf32_Word dyn_seg_size,
    Elf32_Phdr *loadable_segs,
    Elf32_Half num_loadable_segs,
    struct section_info *s_info,
    Elf32_Addr base_addr,
    Elf32_Word dynsym_idx
);


int main(int argc, char *argv[])
{
    FILE *handle;
    Elf32_Ehdr elf_header;
    Elf32_Phdr *loadable_segments = NULL, *seg = NULL;
    Elf32_Shdr null_section = { 0 }, interp = { 0 }, mips_abiflags = { 0 }, reginfo = { 0 };
    Elf32_Half num_loadable_segments, phdr_count;
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

    if (add_section_header(&s_info, "", &null_section) != ORC_SUCCESS)
       goto err_exit;

    /* parse program header info */
    Elf32_Half ph_num = be16toh(elf_header.e_phnum);
    Elf32_Off ph_off = be32toh(elf_header.e_phoff);
    fprintf(stderr, "Found %hu program headers at offset %u\n", ph_num, ph_off);

    switch (find_program_headers(handle, ph_off, ph_num, PT_INTERP, &seg, &phdr_count)) {
        case ORC_SUCCESS:
            interp.sh_addr = seg->p_vaddr;
            interp.sh_addralign = seg->p_align;
            if (seg->p_flags & htobe32(PF_R))
                interp.sh_flags |= htobe32(SHF_ALLOC);
            if (seg->p_flags & htobe32(PF_W))
                interp.sh_flags |= htobe32(SHF_WRITE);
            if (seg->p_flags & htobe32(PF_X))
                interp.sh_flags |= htobe32(SHF_EXECINSTR);
            interp.sh_offset = seg->p_offset;
            interp.sh_size = seg->p_filesz;
            interp.sh_type = htobe32(SHT_PROGBITS);
            if (add_section_header(&s_info, ".interp", &interp) != ORC_SUCCESS)
                goto err_exit;
        case ORC_PHDR_NOT_FOUND:
            break;
        default:
            goto err_exit;
    }

    switch (find_program_headers(handle, ph_off, ph_num, PT_MIPS_ABIFLAGS, &seg, &phdr_count)) {
        case ORC_SUCCESS:
            mips_abiflags.sh_addr = seg->p_vaddr;
            mips_abiflags.sh_addralign = seg->p_align;
            if (seg->p_flags & htobe32(PF_R))
                mips_abiflags.sh_flags |= htobe32(SHF_ALLOC);
            if (seg->p_flags & htobe32(PF_W))
                mips_abiflags.sh_flags |= htobe32(SHF_WRITE);
            if (seg->p_flags & htobe32(PF_X))
                mips_abiflags.sh_flags |= htobe32(SHF_EXECINSTR);
            mips_abiflags.sh_offset = seg->p_offset;
            mips_abiflags.sh_size = seg->p_filesz;
            mips_abiflags.sh_type = htobe32(SHT_MIPS_ABIFLAGS);
            if (add_section_header(&s_info, ".MIPS.abiflags", &mips_abiflags) != ORC_SUCCESS)
                goto err_exit;
        case ORC_PHDR_NOT_FOUND:
            break;
        default:
            goto err_exit;
    }

    switch (find_program_headers(handle, ph_off, ph_num, PT_MIPS_REGINFO, &seg, &phdr_count)) {
        case ORC_SUCCESS:
            reginfo.sh_addr = seg->p_vaddr;
            reginfo.sh_addralign = seg->p_align;
            if (seg->p_flags & htobe32(PF_R))
                reginfo.sh_flags |= htobe32(SHF_ALLOC);
            if (seg->p_flags & htobe32(PF_W))
                reginfo.sh_flags |= htobe32(SHF_WRITE);
            if (seg->p_flags & htobe32(PF_X))
                reginfo.sh_flags |= htobe32(SHF_EXECINSTR);
            reginfo.sh_offset = seg->p_offset;
            reginfo.sh_size = seg->p_filesz;
            reginfo.sh_type = htobe32(SHT_MIPS_REGINFO);
            if (add_section_header(&s_info, ".reginfo", &reginfo) != ORC_SUCCESS)
                goto err_exit;
        case ORC_PHDR_NOT_FOUND:
            break;
        default:
            goto err_exit;
    }

    switch (find_program_headers(handle, ph_off, ph_num, PT_LOAD, &loadable_segments, &num_loadable_segments)) {
        case ORC_SUCCESS:
        case ORC_PHDR_NOT_FOUND:
            break;
        default:
            goto err_exit;
    }

    switch (find_program_headers(handle, ph_off, ph_num, PT_DYNAMIC, &seg, &phdr_count)) {
        case ORC_SUCCESS:
            if ((err = parse_dynamic_segment(handle, seg, loadable_segments, num_loadable_segments, &s_info)) == ORC_CRITICIAL)
                goto err_exit;
        case ORC_PHDR_NOT_FOUND:
            break;
        default:
            goto err_exit;
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
    free(seg);
    free(loadable_segments);
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


enum ORCError parse_dynamic_segment(FILE *handle, Elf32_Phdr *dyn_seg, Elf32_Phdr *loadable_segs, Elf32_Half num_loadable_segs, struct section_info *s_info) {
    /*
        TODO: and subroutines and better error handling to account
        for various architectures and dynamic tag combinations
    */
   /*
    TODO: fill in missing sht_addralign
   */
    enum ORCError err;
    Elf32_Shdr dynamic = { 0 }, dynstr = { 0 }, dynsym = { 0 }, rel_dyn = { 0 }, got = { 0 }, rld_map = { 0 };
    Elf32_Dyn dynamic_tag;
    Elf32_Addr base_addr;
    Elf32_Off dyn_seg_offset = be32toh(dyn_seg->p_offset);
    Elf32_Word dyn_seg_size = be32toh(dyn_seg->p_filesz), syment, symtabno, dynstr_idx, dynsym_idx, mips_local_gotno, mips_gotsym;

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

    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, base_addr, be32toh(dynstr.sh_addr), &dynstr.sh_offset)) != ORC_SUCCESS)
        return err;
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

    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, base_addr, be32toh(dynsym.sh_addr), &dynsym.sh_offset)) != ORC_SUCCESS)
        return err;
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

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_REL, &dynamic_tag))) {
        case ORC_SUCCESS:
            rel_dyn.sh_addr = dynamic_tag.d_un.d_ptr;
            rel_dyn.sh_type = htobe32(SHT_REL);
            fprintf(stderr, "Found DT_REL: %u\n", be32toh(rel_dyn.sh_addr));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_REL dynamic tag\n");
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_RELENT, &dynamic_tag))) {
        case ORC_SUCCESS:
            rel_dyn.sh_entsize = dynamic_tag.d_un.d_val;
            fprintf(stderr, "Found DT_RELENT: %u\n", be32toh(rel_dyn.sh_entsize));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_RELENT dynamic tag\n");
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_RELSZ, &dynamic_tag))) {
        case ORC_SUCCESS:
            rel_dyn.sh_size = dynamic_tag.d_un.d_val;
            fprintf(stderr, "Found DT_RELSZ: %u\n", be32toh(rel_dyn.sh_size));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_RELSZ dynamic tag\n");
        default:
            return err;
    }
    rel_dyn.sh_flags = htobe32(SHF_ALLOC);
    rel_dyn.sh_link = htobe32(dynsym_idx);
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, base_addr, be32toh(rel_dyn.sh_addr), &rel_dyn.sh_offset)) != ORC_SUCCESS)
        return err;
    if ((err = add_section_header(s_info, ".rel.dyn", &rel_dyn)) != ORC_SUCCESS)
        return err;


    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_PLTGOT, &dynamic_tag))) {
        case ORC_SUCCESS:
            got.sh_addr = dynamic_tag.d_un.d_ptr;
            fprintf(stderr, "Found DT_PLTGOT: 0x%x\n", be32toh(got.sh_addr));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_PLTGOT dynamic tag\n");
            break;
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_MIPS_LOCAL_GOTNO, &dynamic_tag))) {
        case ORC_SUCCESS:
            mips_local_gotno = be32toh(dynamic_tag.d_un.d_val);
            fprintf(stderr, "Found DT_MIPS_LOCAL_GOTNO: 0x%x\n", mips_local_gotno);
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_MIPS_LOCAL_GOTNO dynamic tag\n");
            break;
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_MIPS_GOTSYM, &dynamic_tag))) {
        case ORC_SUCCESS:
            mips_gotsym = be32toh(dynamic_tag.d_un.d_val);
            fprintf(stderr, "Found DT_MIPS_GOTSYM: 0x%x\n", mips_gotsym);
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_MIPS_GOTSYM dynamic tag\n");
            break;
        default:
            return err;
    }
    got.sh_addralign = htobe32(16);
    got.sh_entsize = htobe32(4);
    got.sh_flags = htobe32(SHF_ALLOC) | htobe32(SHF_WRITE) | htobe32(SHF_MIPS_GPREL);
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, base_addr, be32toh(got.sh_addr), &got.sh_offset)) != ORC_SUCCESS)
        return err;
    got.sh_size = htobe32(((symtabno - mips_gotsym) + mips_local_gotno) * be32toh(got.sh_entsize));
    got.sh_type = htobe32(SHT_PROGBITS);

    if ((err = add_section_header(s_info, ".got", &got)) != ORC_SUCCESS)
        return err;


    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_MIPS_RLD_MAP, &dynamic_tag))) {
        case ORC_SUCCESS:
            rld_map.sh_addr = dynamic_tag.d_un.d_ptr;
            fprintf(stderr, "Found DT_MIPS_RLD_MAP: 0x%x\n", be32toh(rld_map.sh_addr));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_MIPS_RLD_MAP dynamic tag\n");
            break;
        default:
            return err;
    }
    rld_map.sh_addralign = htobe32(4); /* size of instruction */
    rld_map.sh_flags = htobe32(SHF_ALLOC) | htobe32(SHF_WRITE);
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, base_addr, be32toh(rld_map.sh_addr), &rld_map.sh_offset)) != ORC_SUCCESS)
        return err;
    rld_map.sh_size = htobe32(4); /* size of instruction */
    rld_map.sh_type = htobe32(SHT_PROGBITS);

    if ((err = add_section_header(s_info, ".rld_map", &rld_map)) != ORC_SUCCESS)
        return err;

    parse_mips_nonpic(
        handle,
        dyn_seg_offset,
        dyn_seg_size,
        loadable_segs,
        num_loadable_segs,
        s_info,
        base_addr,
        dynsym_idx
    );

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

enum ORCError find_program_headers(FILE *handle, Elf32_Off ph_off, Elf32_Half ph_num, Elf32_Word seg_type, Elf32_Phdr **phdrs, Elf32_Half *count) {
    Elf32_Phdr phdr;

    if (fseek(handle, ph_off, SEEK_SET) == -1) {
        fprintf(stderr, "Failed to seek to program headers at offset 0x%x: %s\n", ph_off, strerror(errno));
        return ORC_CRITICIAL;
    }

    *count = 0;
    for (Elf32_Half i = 0; i < ph_num; i++) {
        if (fread(&phdr, sizeof(Elf32_Phdr), 1, handle) != 1)
        {
            if (ferror(handle)) {
                fprintf(stderr, "Failed to read program header %hu\n", i);
                return ORC_FILE_IO_ERR;
            }
            fprintf(stderr, "Invalid program headers\n");
            return ORC_INVALID_ELF;
        }
        if (be32toh(phdr.p_type) == seg_type) {
            if (!(*phdrs = reallocarray(*phdrs, *count + 1, sizeof(Elf32_Phdr)))) {
                fprintf(stderr, "Failed to allocate memory %hu program headers: %s\n", *count, strerror(errno));
                return ORC_CRITICIAL;
            }
            memcpy(*phdrs + *count, &phdr, sizeof(Elf32_Phdr));
            (*count)++;
        }
    }
    if (!*count) {
        fprintf(stderr, "Failed to find program headers of type %u\n", seg_type);
        return ORC_PHDR_NOT_FOUND;
    }

    fprintf(stderr, "Found %hu program headers of type %u\n", *count, seg_type);
    return ORC_SUCCESS;
}

enum ORCError calculate_file_offset(Elf32_Phdr *loadable_segs, Elf32_Half num_segs, Elf32_Addr base_addr, Elf32_Addr vaddr, Elf32_Off *file_off) {
    for (Elf32_Half i = 0; i < num_segs; i++) {
        if (be32toh(loadable_segs[i].p_vaddr) < vaddr && vaddr < be32toh(loadable_segs[i].p_vaddr) + be32toh(loadable_segs[i].p_memsz)) {
            *file_off = htobe32(vaddr - ((be32toh(loadable_segs[i].p_vaddr) - be32toh(loadable_segs[i].p_offset) - base_addr) + base_addr));
            fprintf(stderr, "0x%x\n", be32toh(*file_off));
            return ORC_SUCCESS;
        }
    }

    fprintf(stderr, "Failed to find loadable segment containing vaddr 0x%x\n", vaddr);
    return ORC_INVALID_ELF;
}

enum ORCError parse_mips_nonpic(
    FILE *handle,
    Elf32_Off dyn_seg_offset,
    Elf32_Word dyn_seg_size,
    Elf32_Phdr *loadable_segs,
    Elf32_Half num_loadable_segs,
    struct section_info *s_info,
    Elf32_Addr base_addr,
    Elf32_Word dynsym_idx
) {
    Elf32_Shdr rel_plt = { 0 }, got_plt = { 0 }, plt = { 0 };
    Elf32_Dyn dynamic_tag;
    Elf32_Word got_plt_idx;
    enum ORCError err;

    /*
        This will add attempt to add the following sections,
        present in MIPS non-PIC ABI objects:
            * .got.plt
            * .rel.plt
            * .plt
    */

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_PLTREL, &dynamic_tag))) {
        case ORC_SUCCESS:
            if (be32toh(dynamic_tag.d_un.d_val) != DT_REL) {
                fprintf(stderr, "DT_PLTREL has invalid value: %u; MIPS non-PIC ABI expect DT_REL (%u)\n", be32toh(dynamic_tag.d_un.d_val), DT_REL);
                return ORC_DYN_VALUE_INVALID;
            }
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

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_MIPS_PLTGOT, &dynamic_tag))) {
        case ORC_SUCCESS:
            got_plt.sh_addr = dynamic_tag.d_un.d_ptr;
            fprintf(stderr, "Found DT_MIPS_PLTGOT: 0x%x\n", be32toh(got_plt.sh_addr));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_MIPS_PLTGOT dynamic tag\n");
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

    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, base_addr, be32toh(rel_plt.sh_addr), &rel_plt.sh_offset)) != ORC_SUCCESS)
        return err;
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
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, base_addr, be32toh(got_plt.sh_addr), &got_plt.sh_offset)) != ORC_SUCCESS)
        return err;
    got_plt.sh_type = htobe32(SHT_PROGBITS);
    got_plt.sh_flags = htobe32(SHF_ALLOC) | htobe32(SHF_WRITE);
    got_plt.sh_entsize = htobe32(4); /* based on architecture address length */

    got_plt_idx = s_info->num_headers;
    if ((err = add_section_header(s_info, ".got.plt", &got_plt)) != ORC_SUCCESS)
        return err;

    rel_plt.sh_info = htobe32(got_plt_idx);
    if ((err = add_section_header(s_info, ".rel.plt", &rel_plt)) != ORC_SUCCESS)
        return err;


    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_MIPS_RWPLT, &dynamic_tag))) {
        case ORC_SUCCESS:
            plt.sh_addr = dynamic_tag.d_un.d_ptr;
            plt.sh_flags |= htobe32(SHF_WRITE);
            fprintf(stderr, "Found DT_MIPS_RWPLT: 0x%x\n", be32toh(plt.sh_addr));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_MIPS_RWPLT dynamic tag\n");
            break;
        default:
            return err;
    }

    if (!plt.sh_addr) {
        if (fseek(handle, be32toh(got_plt.sh_offset) + 8, SEEK_SET) == -1) {
            fprintf(stderr, "Failed to seek to .got.plt + 8 sectoin at offset 0x%x: %s\n", be32toh(got_plt.sh_offset) + 8, strerror(errno));
            return ORC_CRITICIAL;
        }
        if (fread(&plt.sh_addr, 4, 1, handle) != 1)
        {
            if (ferror(handle)) {
                fprintf(stderr, "Failed to read .got.plt at offset 0x%x\n", be32toh(got_plt.sh_offset) + 8);
                return ORC_FILE_IO_ERR;
            }
            fprintf(stderr, "Invalid .got.plt section\n");
            return ORC_INVALID_ELF;
        }
    }

    plt.sh_addralign = htobe32(32);
    plt.sh_flags |= htobe32(SHF_ALLOC | SHF_EXECINSTR);
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, base_addr, be32toh(plt.sh_addr), &plt.sh_offset)) != ORC_SUCCESS)
        return err;
    /*
        number of MIPS_JUMP_SLOT relocations * 16 + sizeof(PLT header)
        https://sourceware.org/legacy-ml/binutils/2008-07/txt00000.txt
    */
    plt.sh_size = htobe32(((num_jump_slot_relocs > 65535 ? 32 : 16) * num_jump_slot_relocs) + 32);
    plt.sh_type = htobe32(SHT_PROGBITS);

    if ((err = add_section_header(s_info, ".plt", &plt)) != ORC_SUCCESS)
        return err;

    return ORC_SUCCESS;
}