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
*/

struct section_info {
   Elf32_Shdr *headers;
   uint32_t num_headers;

   uint8_t *shstrtab;
   size_t shstrtab_len;
};

enum ORCError {
    ORC_SUCCESS,
    ORC_CRITICIAL,
    ORC_FILE_IO_ERR,
    ORC_INVALID_ELF,
    ORC_DYN_TAG_NOT_FOUND
};

enum ORCError add_section_header(struct section_info *s_info, const char *name, Elf32_Shdr *sh);
enum ORCError find_dynamic_tag(FILE *handle, Elf32_Off dyn_seg_offset, Elf32_Word dyn_seg_size, Elf32_Sword tag, Elf32_Dyn *dynamic_tag);
enum ORCError parse_dynamic_segment(FILE *handle, Elf32_Phdr *dyn_seg, struct section_info *s_info);


int main(int argc, char *argv[])
{
    FILE *handle;
    Elf32_Ehdr elf_header;
    Elf32_Phdr program_header;
    int ret;

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

        program_header.p_type = be32toh(program_header.p_type);
        if (program_header.p_type == PT_DYNAMIC)
            break;
    }

    if (program_header.p_type != PT_DYNAMIC)
    {
        fprintf(stderr, "Failed to find DYNAMIC program header in %s\n", argv[1]);
        return 1;
    }

    // program_header.p_offset = be32toh(program_header.p_offset);
    // program_header.p_vaddr = be32toh(program_header.p_vaddr);
    // program_header.p_paddr = be32toh(program_header.p_paddr);
    // program_header.p_filesz = be32toh(program_header.p_filesz);
    // program_header.p_memsz = be32toh(program_header.p_memsz);
    // fprintf(stderr, "Found DYNAMIC segment:\n\tOffset: 0x%x\n\tVirtualAddress: 0x%x\n\tPhysicalAddress: 0x%x\n\tFileSize: 0x%x\n\tMemorySize: 0x%x\nTagCount: %lu\n",
    //         program_header.p_offset,
    //         program_header.p_vaddr,
    //         program_header.p_paddr,
    //         program_header.p_filesz,
    //         program_header.p_memsz,
    //         program_header.p_filesz/sizeof(Elf32_Dyn));

    /*
        initial vars
    */
   struct section_info s_info = { 0 };
   Elf32_Shdr null_section = { 0 };
   /* uint8_t shstrtab[] = {'\0', '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', '\0'}; */
   if (add_section_header(&s_info, "", &null_section) != ORC_SUCCESS) {
       fprintf(stderr, "Failed to add null section header\n");
       goto err;
   }
    
    /*
        Parse DYNAMIC segment
    */
   parse_dynamic_segment(handle, &program_header, &s_info);

    exit(0);
    /*
        build section headers.p_offset, program_header.p_filesz
     */
    int file_size, shstrtab_offset = 0, sh_offset = 0;
    if (fseek(handle, 0L, SEEK_END) == -1 || (file_size = ftell(handle)) == -1)
    {
        fprintf(stderr, "Failed to obtain file size of %s: %s\n", argv[1], strerror(errno));
        fclose(handle);
        return 1;
    }
    fprintf(stderr, "File %s size: %i bytes\n", argv[1], file_size);

    if (file_size % 32)
    {
        shstrtab_offset = 32 - (file_size % 32);
        if (fseek(handle, shstrtab_offset, SEEK_CUR) == -1)
        {
            fprintf(stderr, "Failed to seek to .shstrtab offset at %i in %s: %s\n", file_size + shstrtab_offset, argv[1], strerror(errno));
            fclose(handle);
            return 1;
        }
    }
    fprintf(stderr, ".shstrtab offset: %i\n", file_size + shstrtab_offset);

    /*
    .shstrtab
    */
    Elf32_Shdr shstrtab_header = {0}, null_header = {0};
    shstrtab_header.sh_name = htobe32(1);
    shstrtab_header.sh_type = htobe32(SHT_STRTAB);
    shstrtab_header.sh_offset = htobe32(file_size + shstrtab_offset);
    shstrtab_header.sh_size = htobe32(11);
    shstrtab_header.sh_addralign = htobe32(1);

/*     if (fwrite(shstrtab, be32toh(shstrtab_header.sh_size), 1, handle) != 1)
    {
        fprintf(stderr, "Failed to write %u byte .shstrtab to %s at offset %u\n", be32toh(shstrtab_header.sh_size), argv[1], file_size + shstrtab_offset);
        fclose(handle);
        return 1;
    }
    fprintf(stderr, "Wrote %u byte .shstrtab to %s at offset %u\n", be32toh(shstrtab_header.sh_size), argv[1], file_size + shstrtab_offset);

    if (be32toh(shstrtab_header.sh_size) % 4)
    {
        sh_offset = 4 - (be32toh(shstrtab_header.sh_size) % 4);
        if (fseek(handle, sh_offset, SEEK_CUR) == -1)
        {
            fprintf(
                stderr,
                "Failed to seek to section header offset at %i in %s: %s\n",
                file_size + shstrtab_offset + be32toh(shstrtab_header.sh_size) + sh_offset,
                argv[1],
                strerror(errno)
            );
            fclose(handle);
            return 1;
        }
    }
    fprintf(stderr, "section header offset: %i\n", file_size + shstrtab_offset + be32toh(shstrtab_header.sh_size) + sh_offset);

    if (fwrite(&null_header, sizeof(Elf32_Shdr), 1, handle) != 1) {
        fprintf(stderr, "Failed to write null section header to %s\n", argv[1]);
        fclose(handle);
        return 1;
    }
    if (fwrite(&shstrtab_header, sizeof(Elf32_Shdr), 1, handle) != 1) {
        fprintf(stderr, "Failed to write .shstrtab section header to %s\n", argv[1]);
        fclose(handle);
        return 1;
    }

    elf_header.e_shentsize = htobe16(sizeof(Elf32_Shdr));
    elf_header.e_shnum = htobe16(2);
    elf_header.e_shoff = htobe32(file_size + shstrtab_offset + be32toh(shstrtab_header.sh_size) + sh_offset);
    elf_header.e_shstrndx = htobe16(1);

    if (fseek(handle, 0, SEEK_SET) == -1 ) {
        fprintf(stderr, "Failed to seek to beginning of %s: %s\n", argv[1], strerror(errno));
        fclose(handle);
        return 1;
    }

    if (fwrite(&elf_header, sizeof(Elf32_Ehdr), 1, handle) != 1) {
        fprintf(stderr, "Failed to write updated ELF header to %s\n", argv[1]);
        fclose(handle);
        return 1;
    }
 */
    ret = 0;
    goto cleanup;

err:
    ret = 1;

cleanup:
    free(s_info.headers);
    free(s_info.shstrtab);
    fclose(handle);
    return ret;
}

enum ORCError add_section_header(struct section_info *s_info, const char *name, Elf32_Shdr *sh) {
    size_t name_len;

    if (!(s_info->headers = reallocarray(s_info->headers, s_info->num_headers + 1, sizeof(Elf32_Shdr)))) {
        fprintf(stderr, "Failed to allocate space for %s section header: %s\n", name, strerror(errno));
        return ORC_CRITICIAL;
    }
    memcpy(s_info->headers + (s_info->num_headers * sizeof(Elf32_Shdr)), sh, sizeof(Elf32_Shdr));
    sh->sh_name = htobe32(s_info->num_headers++);

    name_len = strlen(name) + 1; /* plus terminating \0 */
    if (!(s_info->shstrtab = reallocarray(s_info->shstrtab, s_info->shstrtab_len + name_len, sizeof(uint8_t)))) {
        fprintf(stderr, "Failed to allocate %lu bytes of additional space to add %s to .shstrtab: %s\n", name_len, name, strerror(errno));
        return ORC_CRITICIAL;
    }
    strcpy(s_info->shstrtab + s_info->shstrtab_len, name);
    s_info->shstrtab_len += name_len;

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
    enum ORCError err;
    Elf32_Shdr dynamic = { 0 }, dynstr = { 0 };
    Elf32_Dyn dynamic_tag;
    Elf32_Addr base_addr;
    Elf32_Off dyn_seg_offset = be32toh(dyn_seg->p_offset);
    Elf32_Word dyn_seg_size = be32toh(dyn_seg->p_filesz);

    /*
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
    dynamic.sh_link = dynstr.sh_name;
    dynamic.sh_offset = dyn_seg->p_offset;
    dynamic.sh_size = dyn_seg->p_filesz; /* Practical Binary Analysis, 2.4.3 */
    dynamic.sh_type = htobe32(SHT_DYNAMIC);

    if ((err = add_section_header(s_info, ".dynamic", &dynamic)) != ORC_SUCCESS)
        return err;

    // dynamic.sh_name = htobe32(1);
    // dynamic.sh_type = htobe32(SHT_STRTAB);
    // dynamic.sh_offset = htobe32(file_size + shstrtab_offset);
    // dynamic.sh_size = htobe32(11);
    // dynamic.sh_addralign = htobe32(1);n
    // if ((err = add_section_header(&s_info, "", &dynamic)) != ORC_SUCCESS) {
    //     fprintf(stderr, "Failed to add dynamic section header\n");
    //     return err;
    // }

    return ORC_SUCCESS;
}


enum ORCError find_dynamic_tag(FILE *handle, Elf32_Off dyn_seg_offset, Elf32_Word dyn_seg_size, Elf32_Sword tag, Elf32_Dyn *dynamic_tag) {
   if (fseek(handle, dyn_seg_offset, SEEK_SET) == -1) {
       fprintf(stderr, "Failed to seek to DYNAMIC segment at offset %u: %s\n", dyn_seg_offset, strerror(errno));
       fclose(handle);
       return ORC_CRITICIAL;
   }
    for (Elf32_Word i = 0; i < dyn_seg_size; i += sizeof(Elf32_Dyn)) {
        if (fread(dynamic_tag, sizeof(Elf32_Dyn), 1, handle) != 1)
        {
            if (ferror(handle)) {
                fprintf(stderr, "Failed to read dynamic tag %hu\n", i);
                return ORC_FILE_IO_ERR;
            }
            else {
                fprintf(stderr, "Invalid dynamic tags\n");
                return ORC_INVALID_ELF;
            }

            return 1;
        }

        dynamic_tag->d_tag = be32toh(dynamic_tag->d_tag);
        if (dynamic_tag->d_tag == tag)
            return ORC_SUCCESS;
    }
    fprintf(stderr, "Dynamic tag %u not found\n", tag);
    return ORC_DYN_TAG_NOT_FOUND;

}