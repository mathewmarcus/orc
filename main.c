#include <string.h>
#include <errno.h>

#include <stdint.h>
#include <stdlib.h>
#include <endian.h>
#include <getopt.h>

#include "orc.h"

#define USAGE "%s [ -S section_headers_csv ] [ -s ghidra_symbols_csv ] elf-file\n"
#define SHT_MIPS_ABIFLAGS 0x7000002a /* This is not included in elf.h */
/* Nr,Name,Type,Addr,Offset,Size,EntSize,Flags,Link,Info,Alignment */
#define CSV_FORMAT_STR "%m[^,],%u,0x%08x,0x%08x,%u,%u,%u,%u,%u,%u\n"
#define FUNC_CSV_FORMAT_STR "\"%m[^,\"]\",\"%x\",\"%i\"\n"
#define NUM_DYNSYM_SECTION_LABELS 8

#ifndef STO_MIPS16
#define STO_MIPS16 0xf0
#define ELF_ST_IS_MIPS16(other) (((other) & STO_MIPS16) == STO_MIPS16)
#endif

/* 
    https://github.com/bminor/binutils-gdb/blob/master/binutils/readelf.c#L18968 
    https://github.com/m-labs/uclibc-lm32/blob/master/ldso/ldso/mips/elfinterp.c#L35
*/
#define GP_DISP 0x7ff0
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
    char *name;
    Elf32_Shdr header;

    struct csv_section_header *prev;
    struct csv_section_header *next;

    const char *info;
    const char *link;
};

struct dynsym_section_label {
    const char *name;

    Elf32_Sym symbol;

    struct dynsym_section_label *prev;
    struct dynsym_section_label *next;
};

struct section_info {
   Elf32_Shdr *headers;
   Elf32_Half num_headers;

   uint8_t *shstrtab;
   size_t shstrtab_len;

   struct csv_section_header *csv_headers;

   uint8_t *strtab;
   size_t strtab_len;

   Elf32_Sym *symtab;
   Elf32_Word num_symbols;
};

enum ORCError add_section_header(struct section_info *s_info, const char *name, Elf32_Shdr *sh, const char *link, const char *info);
enum ORCError parse_dynamic_segment(FILE *handle, Elf32_Phdr *dyn_seg, Elf32_Phdr *loadable_segs, Elf32_Half num_loadable_segs, struct section_info *s_info, Elf32_Ehdr *elf_hdr);
enum ORCError parse_mips_nonpic(
    FILE *handle,
    Elf32_Off dyn_seg_offset,
    Elf32_Word dyn_seg_size,
    Elf32_Phdr *loadable_segs,
    Elf32_Half num_loadable_segs,
    struct section_info *s_info
);
enum ORCError parse_dynamic_relocation_section(
    FILE *handle,
    Elf32_Off dyn_seg_offset,
    Elf32_Word dyn_seg_size,
    Elf32_Phdr *loadable_segs,
    Elf32_Half num_loadable_segs,
    struct section_info *s_info
);
enum ORCError zero_elfhdr_sh(FILE *handle, Elf32_Ehdr *elf_hdr);
enum ORCError parse_section_header_csv(const char *csv_filepath, struct section_info *s_info);
enum ORCError parse_gnu_version_requirements_section(
    FILE *handle,
    Elf32_Off dyn_seg_offset,
    Elf32_Word dyn_seg_size,
    Elf32_Phdr *loadable_segs,
    Elf32_Half num_loadable_segs,
    struct section_info *s_info
);
enum ORCError build_section_headers(struct section_info *s_info);
enum ORCError parse_sh_from_dynsym(FILE *handle, Elf32_Phdr *loadable_segs, Elf32_Half num_loadable_segs, struct section_info *s_info);
enum ORCError parse_symtab_from_ghidra_csv(const char *sym_csv_filepath, struct section_info *s_info);
    
static struct dynsym_section_label dynsym_section_labels[NUM_DYNSYM_SECTION_LABELS] = {
    {
        "_init",
        {
            0, STT_FUNC, 0, 0, 0, 0
        },
        NULL,
        NULL
    },
    {
        "_ftext",
        {
            0, STT_NOTYPE, 0, 0, 0, 0
        },
        NULL,
        NULL
    },
    {
        "_fini",
        {
            0, STT_FUNC, 0, 0, 0, 0
        },
        NULL,
        NULL
    },
    {
        "_fdata",
        {
            0, STT_NOTYPE, 0, 0, 0, 0
        },
        NULL,
        NULL
    },
    {
        "_edata",
        {
            0, STT_NOTYPE, 0, 0, 0, 0
        },
        NULL,
        NULL
    },
    {
        "__bss_start",
        {
            0, STT_NOTYPE, 0, 0, 0, 0
        },
        NULL,
        NULL
    },
    {
        "_fbss",
        {
            0, STT_NOTYPE, 0, 0, 0, 0
        },
        NULL,
        NULL
    },
    {
        "_end",
        {
            0, STT_NOTYPE, 0, 0, 0, 0
        },
        NULL,
        NULL
    }
};

int main(int argc, char *argv[])
{
    FILE *handle;
    Elf32_Ehdr elf_header;
    Elf32_Phdr *loadable_segments = NULL, *seg = NULL;
    Elf32_Shdr null_section = { 0 }, interp = { 0 }, mips_abiflags = { 0 }, reginfo = { 0 }, sh = { 0 };
    Elf32_Half num_loadable_segments, phdr_count;
    long offset;
    int ret, opt;
    enum ORCError err;
    struct section_info s_info = { 0 };
    char *csv_file = NULL, *ghidra_symbols_csv = NULL, *ghidra_functions_csv = NULL;
    struct csv_section_header *hdr_ptr;

    opterr = 0;
    while ((opt = getopt(argc, argv, "S:s:")) != -1)
    {
        switch (opt)
        {
        case 'S':
            csv_file = optarg;
            break;
        case 's':
            ghidra_symbols_csv = optarg;
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

    if (add_section_header(&s_info, "", &null_section, NULL, NULL) != ORC_SUCCESS)
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
            if (add_section_header(&s_info, ".interp", &interp, NULL, NULL) != ORC_SUCCESS)
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
            if (add_section_header(&s_info, ".MIPS.abiflags", &mips_abiflags, NULL, NULL) != ORC_SUCCESS)
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
            if (add_section_header(&s_info, ".reginfo", &reginfo, NULL, NULL) != ORC_SUCCESS)
                goto err_exit;
        case ORC_PHDR_NOT_FOUND:
            break;
        default:
            goto err_exit;
    }

    switch (find_program_headers(handle, ph_off, ph_num, PT_GNU_EH_FRAME, &seg, &phdr_count)) {
        case ORC_SUCCESS:
            sh.sh_addr = seg->p_vaddr;
            sh.sh_addralign = seg->p_align;
            if (seg->p_flags & htobe32(PF_R))
                sh.sh_flags |= htobe32(SHF_ALLOC);
            if (seg->p_flags & htobe32(PF_W))
                sh.sh_flags |= htobe32(SHF_WRITE);
            if (seg->p_flags & htobe32(PF_X))
                sh.sh_flags |= htobe32(SHF_EXECINSTR);
            sh.sh_offset = seg->p_offset;
            sh.sh_size = seg->p_filesz;
            sh.sh_type = htobe32(SHT_PROGBITS);
            if (add_section_header(&s_info, ".eh_frame_hdr", &sh, NULL, NULL) != ORC_SUCCESS)
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

    if (csv_file)
        if (parse_section_header_csv(csv_file, &s_info) != ORC_SUCCESS)
            goto err_exit;

    if ((err = parse_sh_from_dynsym(handle, loadable_segments, num_loadable_segments, &s_info)) != ORC_SUCCESS)
        goto err_exit;


    for (hdr_ptr = s_info.csv_headers; hdr_ptr->next; hdr_ptr = hdr_ptr->next) {
        fprintf(stderr, "%s: 0x%x : 0x%x\n", hdr_ptr->name, be32toh(hdr_ptr->header.sh_addr), be32toh(hdr_ptr->header.sh_size));
    }
    fprintf(stderr, "%s: 0x%x : 0x%x\n", hdr_ptr->name, be32toh(hdr_ptr->header.sh_addr), be32toh(hdr_ptr->header.sh_size));


    if (fseek(handle, 0L, SEEK_END) == -1 || (offset = ftell(handle)) == -1)
    {
        fprintf(stderr, "Failed to obtain file size of %s: %s\n", argv[optind], strerror(errno));
        fclose(handle);
        return 1;
    }
    fprintf(stderr, "File %s size: 0x%lx bytes\n", argv[optind], offset);

    Elf32_Word section_end = be32toh(hdr_ptr->header.sh_type) == SHT_NOBITS ? be32toh(hdr_ptr->header.sh_offset): be32toh(hdr_ptr->header.sh_offset) + be32toh(hdr_ptr->header.sh_size);
    if (section_end > offset) {
        if (fseek(handle, section_end-offset, SEEK_CUR) == -1) {
            fprintf(stderr, "Failed to seek to section header end offset at 0x%x in %s: %s\n", section_end, argv[optind], strerror(errno));
            goto err_exit;
        }
        offset = section_end;
    }

    if (ghidra_symbols_csv) {
        if ((err = parse_symtab_from_ghidra_csv(ghidra_symbols_csv, &s_info)) != ORC_SUCCESS)
            goto err_exit;

        if (offset % 4)
        {
            offset += (4 - (offset % 4));
            if (fseek(handle, offset, SEEK_SET) == -1)
            {
                fprintf(stderr, "Failed to seek to .symtab offset at %li in %s: %s\n", offset, argv[optind], strerror(errno));
                goto err_exit;
            }
        }

        if (fwrite(s_info.symtab, sizeof(Elf32_Sym), s_info.num_symbols, handle) != s_info.num_symbols) {
            fprintf(stderr, "Failed to write %hu symbols to %s at offset 0x%lx\n", s_info.num_symbols, argv[optind], offset);
            goto err_exit;
        }
        sh.sh_addr = sh.sh_flags = 0;
        sh.sh_addralign = htobe32(4);
        sh.sh_entsize = htobe32(sizeof(Elf32_Sym));
        /*
            One greater than the symbol table index of the last local symbol. 
            https://docs.oracle.com/cd/E19455-01/806-3773/6jct9o0bs/index.html#elf-15226
            since we are only parsing Global symbols from Ghidra, this will always be 1
        */
        sh.sh_info = htobe32(1);
        sh.sh_offset = htobe32(offset);
        sh.sh_size = htobe32(s_info.num_symbols * sizeof(Elf32_Sym));
        sh.sh_type = htobe32(SHT_SYMTAB);
        if (add_section_header(&s_info, ".symtab", &sh, ".strtab", NULL) != ORC_SUCCESS)
            goto err_exit;
        offset += be32toh(sh.sh_size);

        if (fwrite(s_info.strtab, s_info.strtab_len, 1, handle) != 1)
        {
            fprintf(stderr, "Failed to write %lu byte .strtab to %s at offset 0x%lx\n", s_info.shstrtab_len, argv[optind], offset);
            goto err_exit;
        }
        sh.sh_addr = sh.sh_flags = sh.sh_info = sh.sh_link = sh.sh_entsize = 0;
        sh.sh_addralign = htobe32(1);
        sh.sh_offset = htobe32(offset);
        sh.sh_size = htobe32(s_info.strtab_len);
        sh.sh_type = htobe32(SHT_STRTAB);
        if (add_section_header(&s_info, ".strtab", &sh, NULL, NULL) != ORC_SUCCESS)
            goto err_exit;
        offset += be32toh(sh.sh_size);
    }

    if (offset % 32)
    {
        offset += (32 - (offset % 32));
        if (fseek(handle, offset, SEEK_SET) == -1)
        {
            fprintf(stderr, "Failed to seek to .shstrtab offset at %li in %s: %s\n", offset, argv[optind], strerror(errno));
            goto err_exit;
        }
    }
    fprintf(stderr, ".shstrtab offset: 0x%lx\n", offset);
    fprintf(stderr, "End of last section: 0x%x\n", section_end);


    /*
    .shstrtab
    */
    Elf32_Shdr shstrtab_header = {0};
    shstrtab_header.sh_name = htobe32(s_info.num_headers - 1);
    shstrtab_header.sh_type = htobe32(SHT_STRTAB);
    shstrtab_header.sh_offset = htobe32(offset);
    shstrtab_header.sh_size = htobe32(s_info.shstrtab_len + strlen(".shstrtab") + 1); /* plus terminating \0 */
    shstrtab_header.sh_addralign = htobe32(1);

    if (add_section_header(&s_info, ".shstrtab", &shstrtab_header, NULL, NULL) != ORC_SUCCESS)
        goto err_exit;

    if (build_section_headers(&s_info) != ORC_SUCCESS)
        goto err_exit;

    if (fwrite(s_info.shstrtab, s_info.shstrtab_len, 1, handle) != 1)
    {
        fprintf(stderr, "Failed to write %lu byte .shstrtab to %s at offset 0x%lx\n", s_info.shstrtab_len, argv[optind], offset);
        fclose(handle);
        return 1;
    }
    fprintf(stderr, "Wrote %lu byte .shstrtab to %s at offset 0x%lx\n", s_info.shstrtab_len, argv[optind], offset);

    offset += s_info.shstrtab_len;
    if (offset % 4)
    {
        offset += 4 - (offset % 4);
        if (fseek(handle, offset, SEEK_SET) == -1)
        {
            fprintf(
                stderr,
                "Failed to seek to section header offset at 0x%lx in %s: %s\n",
                offset,
                argv[optind],
                strerror(errno)
            );
            goto err_exit;
        }
    }
    fprintf(stderr, "section header offset: 0x%lx\n", offset);
    fprintf(stderr, "%li\n", ftell(handle));

    if (fwrite(s_info.headers, sizeof(Elf32_Shdr), s_info.num_headers, handle) != s_info.num_headers) {
        fprintf(stderr, "Failed to write %hu section headers to %s\n", s_info.num_headers, argv[optind]);
        fclose(handle);
        return 1;
    }

    elf_header.e_shentsize = htobe16(sizeof(Elf32_Shdr));
    elf_header.e_shnum = htobe16(s_info.num_headers);
    elf_header.e_shoff = htobe32(offset);
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

enum ORCError add_shstrtab_entry(struct section_info *s_info, const char *name, Elf32_Shdr *sh) {
    size_t name_len;

    name_len = strlen(name) + 1; /* plus terminating \0 */
    if (!(s_info->shstrtab = reallocarray(s_info->shstrtab, s_info->shstrtab_len + name_len, sizeof(uint8_t)))) {
        fprintf(stderr, "Failed to allocate %lu bytes of additional space to add %s to .shstrtab: %s\n", name_len, name, strerror(errno));
        return ORC_CRITICIAL;
    }
    strcpy(s_info->shstrtab + s_info->shstrtab_len, name);
    sh->sh_name = htobe32(s_info->shstrtab_len);
    s_info->shstrtab_len += name_len;

    return ORC_SUCCESS;
}

enum ORCError add_section_header(struct section_info *s_info, const char *name, Elf32_Shdr *sh, const char *link, const char *info) {
    enum ORCError err;
    struct csv_section_header *node, *temp;

    if ((err = add_shstrtab_entry(s_info, name, sh)) != ORC_SUCCESS)
        return err;

    if (!(node = malloc(sizeof(struct csv_section_header)))) {
        fprintf(stderr, "Failed to allocate section header node for %s: %s\n", name, strerror(errno));
        return ORC_CRITICIAL;
    }
    memcpy(&node->header, sh, sizeof(Elf32_Shdr));

    node->name = strdup(name);
    node->link = link;
    node->info = info;
    node->prev = NULL;
    node->next = s_info->csv_headers;
    if (s_info->csv_headers)
        s_info->csv_headers->prev = node;

    while (node->next && be32toh(node->header.sh_offset) >= be32toh(node->next->header.sh_offset))
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
    }

    while (node->prev)
        node = node->prev;

    s_info->csv_headers = node;

    return ORC_SUCCESS;
}

int find_referenced_section(struct section_info *s_info, const char *name) {
    int idx = 0;

    for (struct csv_section_header *node = s_info->csv_headers; node != NULL; node = node->next) {
        if (!strcmp(name, node->name))
            return idx;
        idx++;
    }

    return -1;

}

enum ORCError build_section_headers(struct section_info *s_info) {
    Elf32_Shdr *ptr;
    int idx;
    for (struct csv_section_header *node = s_info->csv_headers; node != NULL; node = node->next) {
        if (node->info) {
            if ((idx = find_referenced_section(s_info, node->info)) == -1)
                fprintf(stderr, "Failed to find info section %s for section %s\n", node->info, node->name);
            else
                node->header.sh_info = htobe32(idx);

        }
        if (node->link) {
            if ((idx = find_referenced_section(s_info, node->link)) == -1)
                fprintf(stderr, "Failed to find link section %s for section %s\n", node->info, node->name);
            else
                node->header.sh_link = htobe32(idx);
        }
        s_info->num_headers++;
    }

    if (!(ptr = s_info->headers = calloc(s_info->num_headers, sizeof(Elf32_Shdr)))) {
        fprintf(stderr, "Failed to allocate space for section headers: %s\n", strerror(errno));
        return ORC_CRITICIAL;
    }

    for (struct csv_section_header *node = s_info->csv_headers; node != NULL; node = node->next)
        memcpy(ptr++, &node->header, sizeof(Elf32_Shdr));

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
    Elf32_Shdr dynamic = { 0 }, dynstr = { 0 }, dynsym = { 0 }, got = { 0 }, rld_map = { 0 }, mips_stubs = { 0 }, hash = { 0 }, gnu_version = { 0 };
    Elf32_Dyn dynamic_tag;
    Elf32_Addr base_addr = 0, got_entry;
    Elf32_Off dyn_seg_offset = be32toh(dyn_seg->p_offset), got_off, dynsym_off;
    Elf32_Word dyn_seg_size = be32toh(dyn_seg->p_filesz), syment, symtabno, mips_local_gotno, mips_gotsym, mips_external_gotno, mips_stub_count;
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

    if ((err = add_section_header(s_info, ".dynstr", &dynstr, NULL, NULL)) != ORC_SUCCESS)
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
    dynamic.sh_offset = dyn_seg->p_offset;
    dynamic.sh_size = dyn_seg->p_filesz; /* Practical Binary Analysis, 2.4.3 */
    dynamic.sh_type = htobe32(SHT_DYNAMIC);

    if ((err = add_section_header(s_info, ".dynamic", &dynamic, ".dynstr", NULL)) != ORC_SUCCESS)
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
    /*
        One greater than the symbol table index of the last local symbol. 
        https://docs.oracle.com/cd/E19455-01/806-3773/6jct9o0bs/index.html#elf-15226
        since this is the dynamic string table, this will always be 1
    */
    dynsym.sh_info = htobe32(1);

    if ((err = add_section_header(s_info, ".dynsym", &dynsym, ".dynstr", NULL)) != ORC_SUCCESS)
        return err;

    if ((err = parse_dynamic_relocation_section(
        handle,
        dyn_seg_offset,
        dyn_seg_size,
        loadable_segs,
        num_loadable_segs,
        s_info)) != ORC_SUCCESS) {

        fprintf(stderr, "Failed to parse dynamic relocation section\n");
        return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_VERSYM, &dynamic_tag))) {
        case ORC_SUCCESS: /* https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html */
            gnu_version.sh_addr = dynamic_tag.d_un.d_ptr;
            gnu_version.sh_addralign = gnu_version.sh_entsize = htobe32(sizeof(Elf32_Half));
            gnu_version.sh_flags = htobe32(SHF_ALLOC);
            gnu_version.sh_size = htobe32(symtabno * sizeof(Elf32_Half));
            gnu_version.sh_type = htobe32(SHT_GNU_versym);
            if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(gnu_version.sh_addr), &gnu_version.sh_offset)) != ORC_SUCCESS)
                return err;
            if ((err = add_section_header(s_info, ".gnu.version", &gnu_version, ".dynsym", NULL)) != ORC_SUCCESS)
                return err;

            if ((err = parse_gnu_version_requirements_section(handle, dyn_seg_offset, dyn_seg_size, loadable_segs, num_loadable_segs, s_info)) != ORC_SUCCESS)
                return err;
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_VERSYM dynamic tag\n");
            break;
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_HASH, &dynamic_tag))) {
        case ORC_SUCCESS:
            fprintf(stderr, "Found HASH at 0x%x\n", be32toh(dynamic_tag.d_un.d_ptr));
            // elf_header->e_ident[EI_CLASS] & ELFCLASS64 ? htobe64(8) : htobe32(4)
            hash.sh_addr = dynamic_tag.d_un.d_ptr;
            hash.sh_addralign = hash.sh_entsize = htobe32(sizeof(Elf32_Addr));
            hash.sh_flags = htobe32(SHF_ALLOC);
            hash.sh_offset = dynamic_tag.d_un.d_ptr - htobe32(base_addr);
            if ((err = calculate_hash_size(handle, &hash)) != ORC_SUCCESS)
                return err;
            hash.sh_type = htobe32(SHT_HASH);
            if ((err = add_section_header(s_info, ".hash", &hash, ".dynsym", NULL)) != ORC_SUCCESS)
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

    if ((err = add_section_header(s_info, ".got", &got, NULL, NULL)) != ORC_SUCCESS)
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

            if ((err = add_section_header(s_info, ".rld_map", &rld_map, NULL, NULL)) != ORC_SUCCESS)
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
            s_info
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

        if ((err = add_section_header(s_info, ".MIPS.stubs", &mips_stubs, NULL, NULL)) != ORC_SUCCESS)
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
    struct section_info *s_info
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

    if ((err = add_section_header(s_info, ".got.plt", &got_plt, NULL, NULL)) != ORC_SUCCESS)
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

    if ((err = add_section_header(s_info, ".plt", &plt, NULL, NULL)) != ORC_SUCCESS)
        return err;

    if ((err = add_section_header(s_info, ".rel.plt", &rel_plt, ".dynsym", ".plt")) != ORC_SUCCESS)
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
    struct section_info *s_info
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
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(section_hdr.sh_addr), &section_hdr.sh_offset)) != ORC_SUCCESS)
        return err;
    if ((err = add_section_header(s_info, sh_name, &section_hdr, ".dynsym", NULL)) != ORC_SUCCESS)
        return err;

    return ORC_SUCCESS;
}


enum ORCError parse_section_header_csv(const char *csv_filepath, struct section_info *s_info) {
    FILE *handle;
    int matches;
    char *section_name = NULL;
    Elf32_Shdr header;
    Elf32_Half section_num, index;
    enum ORCError err;

    if (!(handle = fopen(csv_filepath, "r")))
    {
        fprintf(stderr, "Failed to open %s: %s\n", csv_filepath, strerror(errno));
        return ORC_FILE_NOT_FOUND;
    }
    
    while ((matches = fscanf(
        handle,
        CSV_FORMAT_STR,
        &section_name,
        &header.sh_type,
        &header.sh_addr,
        &header.sh_offset,
        &header.sh_size,
        &header.sh_entsize,
        &header.sh_flags,
        &header.sh_link,
        &header.sh_info,
        &header.sh_addralign
    )) == 10) 
    {
        header.sh_type = htobe32(header.sh_type);
        header.sh_addr = htobe32(header.sh_addr);
        header.sh_offset = htobe32(header.sh_offset);
        header.sh_size = htobe32(header.sh_size);
        header.sh_entsize = htobe32(header.sh_entsize);
        header.sh_flags = htobe32(header.sh_flags);
        header.sh_link = htobe32(header.sh_link);
        header.sh_info = htobe32(header.sh_info);
        header.sh_addralign = htobe32(header.sh_addralign);

        if ((err = add_section_header(s_info, section_name, &header, NULL, NULL)) != ORC_SUCCESS)
            goto cleanup;

        free(section_name);
        section_name = NULL;
    }
    
    if (matches != EOF) {
        fprintf(stderr, "Failed to parse section headers from %s: only matches %i of 10 expected columns\n", csv_filepath, matches);
        err = ORC_SECTION_HEADER_CSV_FORMAT_ERR;
        goto cleanup;
    }
    else if (ferror(handle)) {
        fprintf(stderr, "IO error when parsing section headers from %s\n", csv_filepath);
        err = ORC_FILE_IO_ERR;
        goto cleanup;
    }

    err = ORC_SUCCESS;

cleanup:
    free(section_name);
    fclose(handle);

    return err;
}


enum ORCError parse_gnu_version_requirements_section(
    FILE *handle,
    Elf32_Off dyn_seg_offset,
    Elf32_Word dyn_seg_size,
    Elf32_Phdr *loadable_segs,
    Elf32_Half num_loadable_segs,
    struct section_info *s_info
)
{
    enum ORCError err;
    Elf32_Dyn dynamic_tag;
    Elf32_Shdr section_header = { 0 };

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_VERNEED, &dynamic_tag))) {
        case ORC_SUCCESS: /* https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html */
            section_header.sh_addr = dynamic_tag.d_un.d_ptr;
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_VERNEED dynamic tag\n");
        default:
            return err;
    }

    section_header.sh_addralign = htobe32(sizeof(Elf32_Word));
    section_header.sh_flags = htobe32(SHF_ALLOC);
    section_header.sh_type = htobe32(SHT_GNU_verneed);
    if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(section_header.sh_addr), &section_header.sh_offset)) != ORC_SUCCESS)
        return err;

    switch (find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_VERNEEDNUM, &dynamic_tag)) {
        case ORC_SUCCESS: /* https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html */
            section_header.sh_info = dynamic_tag.d_un.d_val;
            if ((err = parse_gnu_version_requirements_size(handle, be32toh(section_header.sh_offset), be32toh(dynamic_tag.d_un.d_val), &section_header.sh_size)) != ORC_SUCCESS)
                return err;
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_VERNEEDNUM dynamic tag\n");
        default:
            return ORC_INVALID_ELF;
    }

    if ((err = add_section_header(s_info, ".gnu.version_r", &section_header, ".dynstr", NULL)) != ORC_SUCCESS)
        return err;

    return ORC_SUCCESS;
}


enum ORCError find_section_header(struct section_info *s_info, const char *section_name, Elf32_Shdr **section_header) {
    for (struct csv_section_header *node = s_info->csv_headers; node != NULL; node = node->next) {
        if (!strcmp(s_info->shstrtab + be32toh(node->header.sh_name), section_name)) {
            *section_header = &node->header;
            return ORC_SUCCESS;
        }
    }

    fprintf(stderr, "header for section %s has not been parsed\n", section_name);
    return ORC_SECTION_NOT_FOUND;
}


enum ORCError parse_dynsym_section_labels(FILE *handle, struct section_info *s_info, struct dynsym_section_label **head) {
    enum ORCError err;
    char *dynstr = NULL;
    Elf32_Shdr *sh;
    Elf32_Word idx;
    struct dynsym_section_label *ptr, *tmp;


    if ((err = find_section_header(s_info, ".dynstr", &sh)) != ORC_SUCCESS)
        goto cleanup;

    if ((err = read_dynstr_table(handle, sh, &dynstr)) != ORC_SUCCESS)
        goto cleanup;

    if ((err = find_section_header(s_info, ".dynsym", &sh)) != ORC_SUCCESS)
        goto cleanup;

    *head = NULL;
    for (int i = 0; i < NUM_DYNSYM_SECTION_LABELS; i++) {    
        switch ((err = find_dynamic_symbol(
            handle,
            dynsym_section_labels[i].name,
            dynsym_section_labels[i].symbol.st_info,
            dynstr,
            sh,
            &dynsym_section_labels[i].symbol,
            &idx
        ))) {
            case ORC_SUCCESS:
                ptr = dynsym_section_labels + i;
                ptr->next = *head;

                if (*head)
                    (*head)->prev = ptr;

                while (ptr->next && be32toh(ptr->symbol.st_value) < be32toh(ptr->next->symbol.st_value))
                {
                    if (ptr->prev != NULL)
                        ptr->prev->next = ptr->next;

                    tmp = ptr->prev;
                    ptr->prev = ptr->next;
                    ptr->next->prev = tmp;

                    tmp = ptr->next->next;
                    ptr->next->next = ptr;
                    ptr->next = tmp;

                    if (ptr->next)
                        ptr->next->prev = ptr;
                }

                for (ptr; ptr->prev; ptr = ptr->prev);
                *head = ptr;

                break;
            case ORC_SYM_NOT_FOUND:
                fprintf(stderr, "dynsym section label %s not found\n", dynsym_section_labels[i].name);
            default:
                goto cleanup;
        }
    }

    for (ptr =  *head; ptr; ptr = ptr->next)
        fprintf(stderr, "%hu: %s: 0x%x\n", be16toh(ptr->symbol.st_shndx), ptr->name, be32toh(ptr->symbol.st_value));

cleanup:
    free(dynstr);
    return err;    
}


enum ORCError parse_sh_from_dynsym(FILE *handle, Elf32_Phdr *loadable_segs, Elf32_Half num_loadable_segs, struct section_info *s_info) {
    enum ORCError err;
    struct dynsym_section_label *label_list;
    uint8_t found_bss = 0;
    Elf32_Shdr sh = { 0 };
    Elf32_Half segment_idx, segment_idx2;
    struct csv_section_header *sh_ptr;
    char *section_name;

    if ((err = parse_dynsym_section_labels(handle, s_info, &label_list)) != ORC_SUCCESS)
        goto cleanup;

    for (struct dynsym_section_label *ptr = label_list; ptr; ptr = ptr->next) {
        fprintf(stderr, "%s\n", ptr->name);
        if (!strcmp(ptr->name, "_end") || ((!strcmp(ptr->name, "_fbss") || !strcmp(ptr->name, "__bss_start")) && found_bss))
            continue;

        /*
            _init, _ftext, and _fini should be in adjacent sections
            If they belong to the same section, then it seems to indicate
            that there is not .init or .fini section
        */
        if (ptr->next && ptr->symbol.st_shndx == ptr->next->symbol.st_shndx && (!strcmp(ptr->name, "_init") || !strcmp(ptr->name, "_fini")) && (!strcmp(ptr->next->name, "_init") || !strcmp(ptr->next->name, "_fini") || !strcmp(ptr->next->name, "_ftext"))) {
            ptr->next->prev = ptr->prev; /* remove from the section label list so it is not used for section boundary calculations */
            continue;
        }

        if (!strcmp(ptr->name, "_edata")) {
            /*
                This is a special case because _edata indicates the end
                of the (sdata) section, not the beginning
            */
            section_name = ".sdata";
            sh.sh_addralign = htobe32(4);
            sh.sh_flags = htobe32(SHF_ALLOC | SHF_WRITE | SHF_MIPS_GPREL);
            sh.sh_type = htobe32(SHT_PROGBITS);

            for (sh_ptr = s_info->csv_headers; sh_ptr->next != NULL && be32toh(sh_ptr->next->header.sh_addr) < be32toh(ptr->symbol.st_value); sh_ptr = sh_ptr->next);

            sh.sh_addr = htobe32(be32toh(sh_ptr->header.sh_addr) + be32toh(sh_ptr->header.sh_size));
            sh.sh_size = htobe32(be32toh(ptr->symbol.st_value) - be32toh(sh.sh_addr));

            if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(sh.sh_addr), &sh.sh_offset)) != ORC_SUCCESS)
                return err;

            ptr->next->prev = ptr->prev; /* remove _edata from the section label list so it is not used for section boundary calculations */
        }
        else {
            sh.sh_addr = ptr->symbol.st_value;
            if ((err = calculate_file_offset(loadable_segs, num_loadable_segs, be32toh(sh.sh_addr), &sh.sh_offset)) != ORC_SUCCESS)
                return err;
            if ((!strcmp(ptr->name, "_fbss") || !strcmp(ptr->name, "__bss_start")) && be32toh(sh.sh_addr) % 16)
                sh.sh_addr = htobe32((16 - (be32toh(sh.sh_addr) % 16)) + be32toh(sh.sh_addr));

            if (ptr->prev == NULL) {
                find_vaddr_segment(loadable_segs, num_loadable_segs, be32toh(sh.sh_addr), &segment_idx);
                sh.sh_size = htobe32((be32toh(loadable_segs[segment_idx].p_vaddr) + be32toh(loadable_segs[segment_idx].p_memsz)) - be32toh(sh.sh_addr));
            }
            else {
                if (ptr->prev->symbol.st_shndx == ptr->symbol.st_shndx || be16toh(ptr->prev->symbol.st_shndx) - be16toh(ptr->symbol.st_shndx) == 1) /* This section is directly adjacent to the previous section */
                    sh.sh_size = htobe32(be32toh(ptr->prev->symbol.st_value) - be32toh(sh.sh_addr));
                else {
                    for (sh_ptr = s_info->csv_headers; sh_ptr->next && be32toh(sh.sh_addr) >= be32toh(sh_ptr->header.sh_addr); sh_ptr = sh_ptr->next);
                    find_vaddr_segment(loadable_segs, num_loadable_segs, be32toh(sh.sh_addr), &segment_idx);
                    find_vaddr_segment(loadable_segs, num_loadable_segs, be32toh(sh_ptr->header.sh_addr), &segment_idx2);

                    sh.sh_size = segment_idx == segment_idx2 ? htobe32(be32toh(sh_ptr->header.sh_addr) - be32toh(sh.sh_addr)): htobe32((be32toh(loadable_segs[segment_idx].p_vaddr) + be32toh(loadable_segs[segment_idx].p_memsz)) - be32toh(sh.sh_addr));
                }
            }

            if (!strcmp(ptr->name, "_init")) {
                section_name = ".init";
                sh.sh_addralign = htobe32(4);
                sh.sh_flags = htobe32(SHF_ALLOC | SHF_EXECINSTR);
                sh.sh_type = htobe32(SHT_PROGBITS);
            }
            else if (!strcmp(ptr->name, "_ftext")) {
                section_name = ".text";
                sh.sh_addralign = htobe32(16);
                sh.sh_flags = htobe32(SHF_ALLOC | SHF_EXECINSTR);
                sh.sh_type = htobe32(SHT_PROGBITS);
            }
            else if (!strcmp(ptr->name, "_fini")) {
                section_name = ".fini";
                sh.sh_addralign = htobe32(4);
                sh.sh_flags = htobe32(SHF_ALLOC | SHF_EXECINSTR);
                sh.sh_type = htobe32(SHT_PROGBITS);

            }
            else if (!strcmp(ptr->name, "_fdata")) {
                section_name = ".data";
                sh.sh_addralign = htobe32(16);
                sh.sh_flags = htobe32(SHF_ALLOC | SHF_WRITE);
                sh.sh_type = htobe32(SHT_PROGBITS);
            }
            else { /* bss */ 
                found_bss = 1;
                section_name = ".bss";
                sh.sh_addralign = htobe32(16);
                sh.sh_flags = htobe32(SHF_ALLOC | SHF_WRITE);
                sh.sh_type = htobe32(SHT_NOBITS);
            }

        }

        if (!sh.sh_size)
            continue;

        if ((err = add_section_header(s_info, section_name, &sh, NULL, NULL)) != ORC_SUCCESS)
            goto cleanup;
    }

cleanup:

    return err;
}


enum ORCError parse_symtab_from_ghidra_csv(const char *sym_csv_filepath, struct section_info *s_info) {
    FILE *sym_file;
    enum ORCError err;
    char *lineptr = NULL, *sym_name;
    size_t buflen = 0, sym_name_len;
    ssize_t line_len;
    Elf32_Sym sym;
    struct csv_section_header *ptr;
    Elf32_Section index;
    int num_matches;

    if (!(sym_file = fopen(sym_csv_filepath, "r")))
    {
        fprintf(stderr, "Failed to open %s: %s\n", sym_csv_filepath, strerror(errno));
        return ORC_FILE_NOT_FOUND;
    }

    for (int line_num = 0; (line_len = getline(&lineptr, &buflen, sym_file)) != -1; line_num++)
    {
        if (line_num == 0)
            continue; /* skip CSV column headers */

        if ((num_matches = sscanf(lineptr, FUNC_CSV_FORMAT_STR, &sym_name, &sym.st_value, &sym.st_size)) != 3) {
            fprintf(stderr, "%s is incorrectly formatted, only matched %i id 3 expected columns in line: %s\n", sym_csv_filepath, num_matches, lineptr);
            err = ORC_SECTION_HEADER_CSV_FORMAT_ERR;
            goto cleanup;
        }

        index = 0;
        for (ptr = s_info->csv_headers; ptr && !(sym.st_value >= be32toh(ptr->header.sh_addr) && sym.st_value + sym.st_size <= be32toh(ptr->header.sh_addr) + be32toh(ptr->header.sh_size)); ptr = ptr->next)
            index++;
        sym.st_shndx = ptr ? index : SHN_UNDEF;

        sym_name_len = strlen(sym_name) + 1;
        if (!(s_info->strtab = realloc(s_info->strtab, s_info->strtab_len + sym_name_len))) {
            fprintf(stderr, "Failed to allocate memory for .strtab section: %s\n", strerror(errno));
            free(sym_name);
            err = ORC_CRITICIAL;
            goto cleanup;
        }
        strcpy(s_info->strtab + s_info->strtab_len, sym_name);
        free(sym_name);
        sym.st_name = s_info->strtab_len;
        s_info->strtab_len += sym_name_len;

        sym.st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);
        sym.st_info = ELF32_ST_INFO(STB_GLOBAL, STT_FUNC);
        sym.st_value = htobe32(sym.st_value);
        sym.st_size = htobe32(sym.st_size);
        sym.st_shndx = htobe16(sym.st_shndx);
        sym.st_name = htobe32(sym.st_name);

        if (!(s_info->symtab = reallocarray(s_info->symtab, s_info->num_symbols + 1, sizeof(Elf32_Sym)))) {
            fprintf(stderr, "Failed to allocate memory for .symtab section: %s\n", strerror(errno));
            err = ORC_CRITICIAL;
            goto cleanup;
        }
        memcpy(s_info->symtab + s_info->num_symbols++, &sym, sizeof(Elf32_Sym));
    }

    fprintf(stderr, "Parsed %u symbols from %s\n", s_info->num_symbols, sym_csv_filepath);
    
cleanup:
    free(lineptr);
    fclose(sym_file);

    return err;
}