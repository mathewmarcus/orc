#include <string.h>
#include <errno.h>

#include <stdint.h>
#include <stdlib.h>
#include <endian.h>
#include <getopt.h>

#include "orc.h"

#define USAGE "%s [ -S section_headers_csv ] elf-file\n"
#define SHT_MIPS_ABIFLAGS 0x7000002a /* This is not included in elf.h */
/* Nr,Name,Type,Addr,Offset,Size,EntSize,Flags,Link,Info,Alignment */
#define CSV_FORMAT_STR "%hu,%m[^,],%u,0x%08x,0x%08x,%u,%u,%u,%u,%u,%u\n"
/*
    TODO:
        label section
        .fdata .data
        __RLD_MAP .rld_map
        _fbss,__bss_start .bss
*/

/*
    Program Headers

            .MIPS.stubs

    dynamic section entries

    DT_MIPS_RLD_MAP .rld_map

    For nonPIC (with PLT):
    musl-gcc -fno-PIC -mips16 hello_world.c -mno-abicalls -o hello_world16e_nopic

    For nonPIC (with PLT) and partial RELRO (both .got and .got.plt are writable):
    musl-gcc -z relro -fno-PIC -mips16 hello_world.c -mno-abicalls -o hello_world16e_nopic

    For nonPIC (with PLT) and "full" RELRO (only .got is writable):
    musl-gcc -z relro -z now -fno-PIC -mips16 hello_world.c -mno-abicalls -o hello_world16e_nopic
*/

struct csv_section_header {
    Elf32_Half index;
    char *name;
    Elf32_Shdr header;

    struct csv_section_header *prev;
    struct csv_section_header *next;
};

struct section_info {
   Elf32_Shdr *headers;
   Elf32_Half num_headers;

   uint8_t *shstrtab;
   size_t shstrtab_len;

   struct csv_section_header *csv_headers;
};

enum ORCError add_section_header(struct section_info *s_info, const char *name, Elf32_Shdr *sh);
enum ORCError parse_dynamic_segment(FILE *handle, Elf32_Phdr *dyn_seg, Elf32_Phdr *loadable_segs, Elf32_Half num_loadable_segs, struct section_info *s_info, Elf32_Ehdr *elf_hdr);
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
enum ORCError parse_dynamic_relocation_section(
    FILE *handle,
    Elf32_Off dyn_seg_offset,
    Elf32_Word dyn_seg_size,
    Elf32_Phdr *loadable_segs,
    Elf32_Half num_loadable_segs,
    struct section_info *s_info,
    Elf32_Word dynsym_idx
);
enum ORCError zero_elfhdr_sh(FILE *handle, Elf32_Ehdr *elf_hdr);
static enum ORCError _add_section_header(struct section_info *s_info, const char *name, Elf32_Shdr *sh);
enum ORCError parse_section_header_csv(const char *csv_filepath, struct section_info *s_info);

int main(int argc, char *argv[])
{
    FILE *handle;
    Elf32_Ehdr elf_header;
    Elf32_Phdr *loadable_segments = NULL, *seg = NULL;
    Elf32_Shdr null_section = { 0 }, interp = { 0 }, mips_abiflags = { 0 }, reginfo = { 0 };
    Elf32_Half num_loadable_segments, phdr_count;
    long file_size, shstrtab_offset = 0, sh_offset = 0;
    int ret, opt;
    enum ORCError err;
    struct section_info s_info = { 0 };

    opterr = 0;
    while ((opt = getopt(argc, argv, "S:")) != -1)
    {
        switch (opt)
        {
        case 'S':
            if (parse_section_header_csv(optarg, &s_info) != ORC_SUCCESS)
                return 1;
            break;
        case '?':
        default:
            fprintf(stderr, USAGE, argv[0]);
            return 1;
        }
    }
    

    if (argc - optind != 1)
    {
        fprintf(stderr, USAGE, argv[0]);
        return 1;
    }

    if (!(handle = fopen(argv[optind], "r+")))
    {
        fprintf(stderr, "Failed to open %s: %s\n", argv[optind], strerror(errno));
        return 1;
    }

    if (fread(&elf_header, sizeof(Elf32_Ehdr), 1, handle) != 1)
    {
        if (ferror(handle))
            fprintf(stderr, "Failed to read ELF header from %s\n", argv[optind]);
        else
            fprintf(stderr, "No ELF header found in %s\n", argv[optind]);

        fclose(handle);
        return 1;
    }

    if (!IS_SUPPORTED_ARCH((&elf_header))) {
        fprintf(stderr, "Currently only 32 bit big-endian MIPS binaries are supported\n");
        goto err_exit;
    }

    if (elf_header.e_shoff || elf_header.e_shnum) {
        fprintf(stderr, "%s already contains %hu section headers at offset 0x%x\n", argv[optind], be16toh(elf_header.e_shnum), be32toh(elf_header.e_shoff));
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
            if ((err = parse_dynamic_segment(handle, seg, loadable_segments, num_loadable_segments, &s_info, &elf_header)) == ORC_CRITICIAL)
                goto err_exit;
        case ORC_PHDR_NOT_FOUND:
            break;
        default:
            goto err_exit;
    }

    if (fseek(handle, 0L, SEEK_END) == -1 || (file_size = ftell(handle)) == -1)
    {
        fprintf(stderr, "Failed to obtain file size of %s: %s\n", argv[optind], strerror(errno));
        fclose(handle);
        return 1;
    }
    fprintf(stderr, "File %s size: %li bytes\n", argv[optind], file_size);

    if (file_size % 32)
    {
        shstrtab_offset = 32 - (file_size % 32);
        if (fseek(handle, shstrtab_offset, SEEK_CUR) == -1)
        {
            fprintf(stderr, "Failed to seek to .shstrtab offset at %li in %s: %s\n", file_size + shstrtab_offset, argv[optind], strerror(errno));
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
        fprintf(stderr, "Failed to write %lu byte .shstrtab to %s at offset %li\n", s_info.shstrtab_len, argv[optind], file_size + shstrtab_offset);
        fclose(handle);
        return 1;
    }
    fprintf(stderr, "Wrote %lu byte .shstrtab to %s at offset %li\n", s_info.shstrtab_len, argv[optind], file_size + shstrtab_offset);

    if (s_info.shstrtab_len % 4)
    {
        sh_offset = 4 - (s_info.shstrtab_len % 4);
        if (fseek(handle, sh_offset, SEEK_CUR) == -1)
        {
            fprintf(
                stderr,
                "Failed to seek to section header offset at %lu in %s: %s\n",
                file_size + shstrtab_offset + s_info.shstrtab_len + sh_offset,
                argv[optind],
                strerror(errno)
            );
            fclose(handle);
            return 1;
        }
    }
    fprintf(stderr, "section header offset: %li\n", file_size + shstrtab_offset + s_info.shstrtab_len + sh_offset);
    fprintf(stderr, "%li\n", ftell(handle));

    if (fwrite(s_info.headers, sizeof(Elf32_Shdr), s_info.num_headers, handle) != s_info.num_headers) {
        fprintf(stderr, "Failed to write %hu section headers to %s\n", s_info.num_headers, argv[optind]);
        fclose(handle);
        return 1;
    }

    elf_header.e_shentsize = htobe16(sizeof(Elf32_Shdr));
    elf_header.e_shnum = htobe16(s_info.num_headers);
    elf_header.e_shoff = htobe32(file_size + shstrtab_offset + s_info.shstrtab_len + sh_offset);
    elf_header.e_shstrndx = htobe16(s_info.num_headers - 1);

    if (fseek(handle, 0, SEEK_SET) == -1) {
        fprintf(stderr, "Failed to seek to beginning of %s: %s\n", argv[optind], strerror(errno));
        fclose(handle);
        return 1;
    }

    if (fwrite(&elf_header, sizeof(Elf32_Ehdr), 1, handle) != 1) {
        fprintf(stderr, "Failed to write updated ELF header to %s\n", argv[optind]);
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
    enum ORCError err;
    struct csv_section_header *node;

    for (struct csv_section_header *node = s_info->csv_headers; node != NULL; node = node->next) {
        if (s_info->num_headers != node->index)
            continue;
        
        if ((err = _add_section_header(s_info, node->name, &node->header)) != ORC_SUCCESS)
            return err;

        // if (node->prev)
        //     node->prev->next = node->next;
        // if (node->next)
        //     node->next->prev = node->prev;
        // free(node);
    }
    return _add_section_header(s_info, name, sh);
}

static enum ORCError _add_section_header(struct section_info *s_info, const char *name, Elf32_Shdr *sh) {
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


enum ORCError parse_dynamic_segment(FILE *handle, Elf32_Phdr *dyn_seg, Elf32_Phdr *loadable_segs, Elf32_Half num_loadable_segs, struct section_info *s_info, Elf32_Ehdr *elf_hdr) {
    /*
        TODO: and subroutines and better error handling to account
        for various architectures and dynamic tag combinations
    */
   /*
    TODO: fill in missing sht_addralign
   */
    enum ORCError err;
    Elf32_Shdr dynamic = { 0 }, dynstr = { 0 }, dynsym = { 0 }, got = { 0 }, rld_map = { 0 }, mips_stubs = { 0 }, hash = { 0 };
    Elf32_Dyn dynamic_tag;
    Elf32_Addr base_addr = 0, got_entry;
    Elf32_Off dyn_seg_offset = be32toh(dyn_seg->p_offset), got_off, dynsym_off;
    Elf32_Word dyn_seg_size = be32toh(dyn_seg->p_filesz), syment, symtabno, dynstr_idx, dynsym_idx, mips_local_gotno, mips_gotsym, mips_external_gotno, mips_stub_count;
    Elf32_Sym sym;
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

    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(dynstr.sh_addr), &dynstr.sh_offset)) != ORC_SUCCESS)
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

    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(dynsym.sh_addr), &dynsym.sh_offset)) != ORC_SUCCESS)
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

    if ((err = parse_dynamic_relocation_section(
        handle,
        dyn_seg_offset,
        dyn_seg_size,
        loadable_segs,
        num_loadable_segs,
        s_info,
        dynsym_idx)) != ORC_SUCCESS) {

        fprintf(stderr, "Failed to parse dynamic relocation section\n");
        return err;
    }


    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_HASH, &dynamic_tag))) {
        case ORC_SUCCESS:
            fprintf(stderr, "Found HASH at 0x%x\n", be32toh(dynamic_tag.d_un.d_ptr));
            // elf_header->e_ident[EI_CLASS] & ELFCLASS64 ? htobe64(8) : htobe32(4)
            hash.sh_addr = dynamic_tag.d_un.d_ptr;
            hash.sh_addralign = hash.sh_entsize = htobe32(sizeof(Elf32_Addr));
            hash.sh_flags = htobe32(SHF_ALLOC);
            hash.sh_link = htobe32(dynsym_idx);
            hash.sh_offset = dynamic_tag.d_un.d_ptr - htobe32(base_addr);
            if ((err = calculate_hash_size(handle, &hash)) != ORC_SUCCESS)
                return err;
            hash.sh_type = htobe32(SHT_HASH);
            if ((err = add_section_header(s_info, ".hash", &hash)) != ORC_SUCCESS)
                return err;
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_HASH dynamic tag\n");
            break;
        default:
            return err;
    }


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
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(got.sh_addr), &got.sh_offset)) != ORC_SUCCESS)
        return err;
    got.sh_size = htobe32(((symtabno - mips_gotsym) + mips_local_gotno) * be32toh(got.sh_entsize));
    got.sh_type = htobe32(SHT_PROGBITS);

    if ((err = add_section_header(s_info, ".got", &got)) != ORC_SUCCESS)
        return err;


    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_MIPS_RLD_MAP, &dynamic_tag))) {
        case ORC_SUCCESS:
            rld_map.sh_addr = dynamic_tag.d_un.d_ptr;
            fprintf(stderr, "Found DT_MIPS_RLD_MAP: 0x%x\n", be32toh(rld_map.sh_addr));
            rld_map.sh_addralign = htobe32(4); /* size of instruction */
            rld_map.sh_flags = htobe32(SHF_ALLOC) | htobe32(SHF_WRITE);
            if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(rld_map.sh_addr), &rld_map.sh_offset)) != ORC_SUCCESS)
                return err;
            rld_map.sh_size = htobe32(4); /* size of instruction */
            rld_map.sh_type = htobe32(SHT_PROGBITS);

            if ((err = add_section_header(s_info, ".rld_map", &rld_map)) != ORC_SUCCESS)
                return err;
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_MIPS_RLD_MAP dynamic tag\n");
            break;
        default:
            return err;
    }

    if (IS_MIPS_NONPIC(elf_hdr)) {
        err = parse_mips_nonpic(
            handle,
            dyn_seg_offset,
            dyn_seg_size,
            loadable_segs,
            num_loadable_segs,
            s_info,
            base_addr,
            dynsym_idx
        );
        if (err != ORC_SUCCESS)
            return err;
    }


    //fseek dynsym + (SYMENT * MIPS_GOTSYM)

    /*
        parse MIPS stubs
    */
    mips_external_gotno = symtabno - mips_gotsym;
    got_off = be32toh(got.sh_offset) + (be32toh(got.sh_entsize) * mips_local_gotno);
    dynsym_off = be32toh(dynsym.sh_offset) + (be32toh(dynsym.sh_entsize) * mips_gotsym);
    fprintf(stderr, "GOT offset: 0x%x\ndynsym offset: 0x%x\nnum external gotno: %u\n", got_off, dynsym_off, mips_external_gotno);

    err = get_mips_stub_info(
        handle,
        mips_external_gotno,
        got_off,
        dynsym_off,
        be32toh(got.sh_entsize),
        be32toh(dynsym.sh_entsize),
        &mips_stub_count,
        &mips_stubs.sh_addr
    );
    if (err != ORC_SUCCESS) {
        fprintf(stderr, "Failed to build .MIPS.stubs section\n");
        return err;
    }
    if (!mips_stub_count)
        fprintf(stderr, "No .MIPS.stubs detected\n");
    else {
        mips_stubs.sh_addralign = htobe32(sizeof(Elf32_Addr));
        mips_stubs.sh_flags = htobe32(SHF_ALLOC) | htobe32(SHF_EXECINSTR);
        if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(mips_stubs.sh_addr), &mips_stubs.sh_offset)) != ORC_SUCCESS)
            return err;
        mips_stubs.sh_size = htobe32(sizeof(Elf32_Addr) * 4 * (mips_stub_count + 1)); /* are stubs always 4 instructions? are they always terminated with a null stub? */
        mips_stubs.sh_type = htobe32(SHT_PROGBITS);

        if ((err = add_section_header(s_info, ".MIPS.stubs", &mips_stubs)) != ORC_SUCCESS)
            return err;
    }

    return ORC_SUCCESS;
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
    enum ORCError err;

    /*
        This will add attempt to add the following sections,
        present in MIPS non-PIC ABI objects:
            * .got.plt
            * .rel.plt
            * .plt
    */

    if ((err = parse_rel_plt_from_dyn_seg(handle, dyn_seg_offset, dyn_seg_size, &rel_plt)) != ORC_SUCCESS)
        return err;

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

    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(rel_plt.sh_addr), &rel_plt.sh_offset)) != ORC_SUCCESS)
        return err;
    /*
        This section headers sh_info field holds a section header table index.
        https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-94076.html
    */
    rel_plt.sh_flags = htobe32(SHF_ALLOC) | htobe32(SHF_INFO_LINK);
    rel_plt.sh_link = htobe32(dynsym_idx);
    rel_plt.sh_type = htobe32(SHT_REL);

    Elf32_Word num_jump_slot_relocs;
    if ((err = count_mips_jump_slot_relocs(handle, be32toh(rel_plt.sh_offset), be32toh(rel_plt.sh_size), &num_jump_slot_relocs)) != ORC_SUCCESS)
        return err;

    /* 
        number of R_MIPS_JUMP_SLOT in .rel.plt + pltgot[0] (dynamic linker's PLT resolver) + pltgot[1] (object link map)
        multiplied by the size of a MIPS32 address (4 bytes)

    */
    got_plt.sh_size = htobe32((num_jump_slot_relocs + 2) * 4);
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(got_plt.sh_addr), &got_plt.sh_offset)) != ORC_SUCCESS)
        return err;
    got_plt.sh_type = htobe32(SHT_PROGBITS);
    got_plt.sh_flags = htobe32(SHF_ALLOC) | htobe32(SHF_WRITE);
    got_plt.sh_entsize = htobe32(4); /* based on architecture address length */

    if ((err = add_section_header(s_info, ".got.plt", &got_plt)) != ORC_SUCCESS)
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
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(plt.sh_addr), &plt.sh_offset)) != ORC_SUCCESS)
        return err;
    /*
        number of MIPS_JUMP_SLOT relocations * 16 + sizeof(PLT header)
        https://sourceware.org/legacy-ml/binutils/2008-07/txt00000.txt
    */
    plt.sh_size = htobe32(((num_jump_slot_relocs > 65535 ? 32 : 16) * num_jump_slot_relocs) + 32);
    plt.sh_type = htobe32(SHT_PROGBITS);

    if ((err = add_section_header(s_info, ".plt", &plt)) != ORC_SUCCESS)
        return err;

    rel_plt.sh_info = htobe32(s_info->num_headers - 1);
    if ((err = add_section_header(s_info, ".rel.plt", &rel_plt)) != ORC_SUCCESS)
        return err;

    return ORC_SUCCESS;
}


enum ORCError zero_elfhdr_sh(FILE *handle, Elf32_Ehdr *elf_hdr) {
    if (fseek(handle, 0, SEEK_SET) == -1) {
        fprintf(stderr, "Failed to seek to beginning of file: %s\n", strerror(errno));
        return ORC_FILE_IO_ERR;
    }

    elf_hdr->e_shoff = elf_hdr->e_shnum = elf_hdr->e_shentsize = elf_hdr->e_shstrndx = 0;

    if (fwrite(elf_hdr, sizeof(Elf32_Ehdr), 1, handle) != 1) {
        fprintf(stderr, "Failed to zero out section header info in ELF header\n");
        return ORC_FILE_IO_ERR;
    }

    fprintf(stderr, "Zeroed out section header info in ELF header\n");
    return ORC_SUCCESS;
}


enum ORCError parse_dynamic_relocation_section(
    FILE *handle,
    Elf32_Off dyn_seg_offset,
    Elf32_Word dyn_seg_size,
    Elf32_Phdr *loadable_segs,
    Elf32_Half num_loadable_segs,
    struct section_info *s_info,
    Elf32_Word dynsym_idx
) {
    enum ORCError err;
    Elf32_Dyn dynamic_tag;
    Elf32_Shdr section_hdr = { 0 };
    Elf32_Sword reloc_entry_size_tag, reloc_table_size_tag;
    char *reloc_entry_size_tag_name, *reloc_table_size_tag_name, *sh_name;


    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_REL, &dynamic_tag))) {
        case ORC_SUCCESS:
            section_hdr.sh_addr = dynamic_tag.d_un.d_ptr;
            section_hdr.sh_type = htobe32(SHT_REL);
            reloc_entry_size_tag = DT_RELENT;
            reloc_table_size_tag = DT_RELSZ;
            reloc_entry_size_tag_name = "DT_RELENT";
            reloc_table_size_tag_name = "DT_RELSZ";
            sh_name = ".rel.dyn";
            fprintf(stderr, "Found DT_REL: 0x%x\n", be32toh(section_hdr.sh_addr));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_REL dynamic tag\n");
            switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_RELA, &dynamic_tag))) {
                case ORC_SUCCESS:
                    section_hdr.sh_addr = dynamic_tag.d_un.d_ptr;
                    section_hdr.sh_type = htobe32(SHT_RELA);
                    reloc_entry_size_tag = DT_RELAENT;
                    reloc_table_size_tag = DT_RELASZ;
                    reloc_entry_size_tag_name = "DT_RELAENT";
                    reloc_table_size_tag_name = "DT_RELASZ";
                    sh_name = ".rela.dyn";
                    fprintf(stderr, "Found DT_RELA: 0x%x\n", be32toh(section_hdr.sh_addr));
                    break;
                case ORC_DYN_TAG_NOT_FOUND: /* This means there are not dynamic relocations */
                    fprintf(stderr, "Failed to find DT_RELA dynamic tag\n");
                    err = ORC_SUCCESS;
            }
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, reloc_entry_size_tag, &dynamic_tag))) {
        case ORC_SUCCESS:
            section_hdr.sh_entsize = dynamic_tag.d_un.d_val;
            fprintf(stderr, "Found %s: %u\n", reloc_entry_size_tag_name, be32toh(section_hdr.sh_entsize));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find %s dynamic tag\n", reloc_entry_size_tag_name);
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, reloc_table_size_tag, &dynamic_tag))) {
        case ORC_SUCCESS:
            section_hdr.sh_size = dynamic_tag.d_un.d_val;
            fprintf(stderr, "Found %s: %u\n", reloc_table_size_tag_name, be32toh(section_hdr.sh_size));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find %s dynamic tag\n", reloc_table_size_tag_name);
        default:
            return err;
    }
    section_hdr.sh_flags = htobe32(SHF_ALLOC);
    section_hdr.sh_link = htobe32(dynsym_idx);
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(section_hdr.sh_addr), &section_hdr.sh_offset)) != ORC_SUCCESS)
        return err;
    if ((err = add_section_header(s_info, sh_name, &section_hdr)) != ORC_SUCCESS)
        return err;

    return ORC_SUCCESS;
}


enum ORCError parse_section_header_csv(const char *csv_filepath, struct section_info *s_info) {
    FILE *handle;
    int matches;
    char *section_name;
    Elf32_Shdr sh;
    Elf32_Addr end;
    Elf32_Half section_num;
    struct csv_section_header *node, *temp;

    if (!(handle = fopen(csv_filepath, "r")))
    {
        fprintf(stderr, "Failed to open %s: %s\n", csv_filepath, strerror(errno));
        return ORC_FILE_NOT_FOUND;
    }

    if (!(node = malloc(sizeof(struct csv_section_header)))) {
        fprintf(stderr, "Failed to allocate head of CSV section header linked-list: %s\n", strerror(errno));
        return ORC_CRITICIAL;
    }
    node->next = NULL;
    
    while ((matches = fscanf(
        handle,
        CSV_FORMAT_STR,
        &node->index,
        &node->name,
        &node->header.sh_type,
        &node->header.sh_addr,
        &node->header.sh_offset,
        &node->header.sh_size,
        &node->header.sh_entsize,
        &node->header.sh_flags,
        &node->header.sh_link,
        &node->header.sh_info,
        &node->header.sh_addralign
    )) == 11) 
    {
        node->header.sh_type = htobe32(node->header.sh_type);
        node->header.sh_addr = htobe32(node->header.sh_addr);
        node->header.sh_offset = htobe32(node->header.sh_offset);
        node->header.sh_size = htobe32(node->header.sh_size);
        node->header.sh_entsize = htobe32(node->header.sh_entsize);
        node->header.sh_flags = htobe32(node->header.sh_flags);
        node->header.sh_link = htobe32(node->header.sh_link);
        node->header.sh_info = htobe32(node->header.sh_info);
        node->header.sh_addralign = htobe32(node->header.sh_addralign);

        node->prev = NULL;
        while (node->next && node->index > node->next->index)
        {
            if (node->prev != NULL)
                node->prev->next = node->next;

            temp = node->prev;
            node->prev = node->next;
            node->next->prev = temp;

            temp = node->next->next;
            node->next->next = node;
            node->next = temp;

            if (node->next)
                node->next->prev = node;

            // fprintf(stderr, "curr: %hu, next: %p\n", node->index, node->next);
        }

        while (node->prev) {
            node = node->prev;
        }
        fprintf(stderr, "\n");

        if (!(node->prev = malloc(sizeof(struct csv_section_header)))) {
            fprintf(stderr, "Failed to allocate node in CSV section header linked-list: %s\n", strerror(errno));
            return ORC_CRITICIAL;
        }
        node->prev->next = node;
        node = node->prev;
    }
    if (node->next)
        node->next->prev = NULL;
    s_info->csv_headers = node->next;
    free(node);

    
    if (matches != EOF) {
        fprintf(stderr, "Failed to parse section headers from %s: only matches %i of 10 expected columns\n", csv_filepath, matches);
        return ORC_SECTION_HEADER_CSV_FORMAT_ERR;
    }
    else if (ferror(handle)) {
        fprintf(stderr, "IO error when parsing section headers from %s\n", csv_filepath);
        return ORC_FILE_IO_ERR;
    }

    for (struct csv_section_header *node = s_info->csv_headers; node != NULL; node = node->next)
        fprintf(stderr, "CSV header %u %s\n", node->index, node->name);
    return ORC_SUCCESS;

}