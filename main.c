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

int main(int argc, char *argv[])
{
    FILE *handle;
    uint8_t elf_header[sizeof(Elf32_Ehdr)], program_header[sizeof(Elf32_Phdr)];
    Elf32_Ehdr *elf_header_ptr = (Elf32_Ehdr *)elf_header;
    Elf32_Phdr *program_header_ptr = (Elf32_Phdr *)program_header;

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

    if (fread(elf_header, 1, sizeof(Elf32_Ehdr), handle) != sizeof(Elf32_Ehdr))
    {
        if (ferror(handle))
            fprintf(stderr, "Failed to read ELF header from %s\n", argv[1]);
        else
            fprintf(stderr, "No ELF header found in %s\n", argv[1]);

        fclose(handle);
        return 1;
    }

    /* parse program header info */
    Elf32_Half ph_num = be16toh(elf_header_ptr->e_phnum), ph_size = be16toh(elf_header_ptr->e_phentsize);
    Elf32_Off ph_off = be32toh(elf_header_ptr->e_phoff);
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
        if (fread(program_header, 1, sizeof(Elf32_Phdr), handle) != sizeof(Elf32_Phdr))
        {
            if (ferror(handle))
                fprintf(stderr, "Failed to read program header %hu from %s\n", i, argv[1]);
            else
                fprintf(stderr, "Invalid program headers found in %s\n", argv[1]);

            fclose(handle);
            return 1;
        }

        program_header_ptr->p_type = be32toh(program_header_ptr->p_type);
        if (program_header_ptr->p_type == PT_DYNAMIC)
            break;
    }

    if (program_header_ptr->p_type != PT_DYNAMIC)
    {
        fprintf(stderr, "Failed to find DYNAMIC program header in %s\n", argv[1]);
        return 1;
    }

    program_header_ptr->p_offset = be32toh(program_header_ptr->p_offset);
    program_header_ptr->p_vaddr = be32toh(program_header_ptr->p_vaddr);
    program_header_ptr->p_paddr = be32toh(program_header_ptr->p_paddr);
    program_header_ptr->p_filesz = be32toh(program_header_ptr->p_filesz);
    program_header_ptr->p_memsz = be32toh(program_header_ptr->p_memsz);
    fprintf(stderr, "Found DYNAMIC segment:\n\tOffset: 0x%x\n\tVirtualAddress: 0x%x\n\tPhysicalAddress: 0x%x\n\tFileSize: 0x%x\n\tMemorySize: 0x%x\n",
            program_header_ptr->p_offset,
            program_header_ptr->p_vaddr,
            program_header_ptr->p_paddr,
            program_header_ptr->p_filesz,
            program_header_ptr->p_memsz);

    /*
        build section headers
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
    uint8_t shstrtab[] = {'\0', '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', '\0'};
    Elf32_Shdr shstrtab_header = {0}, null_header = {0};
    shstrtab_header.sh_name = htobe32(1);
    shstrtab_header.sh_type = htobe32(SHT_STRTAB);
    shstrtab_header.sh_offset = htobe32(file_size + shstrtab_offset);
    shstrtab_header.sh_size = htobe32(11);
    shstrtab_header.sh_addralign = htobe32(1);

    if (fwrite(shstrtab, be32toh(shstrtab_header.sh_size), 1, handle) != 1)
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

    elf_header_ptr->e_shentsize = htobe16(sizeof(Elf32_Shdr));
    elf_header_ptr->e_shnum = htobe16(2);
    elf_header_ptr->e_shoff = htobe32(file_size + shstrtab_offset + be32toh(shstrtab_header.sh_size) + sh_offset);
    elf_header_ptr->e_shstrndx = htobe16(1);

    if (fseek(handle, 0, SEEK_SET) == -1 ) {
        fprintf(stderr, "Failed to seek to beginning of %s: %s\n", argv[1], strerror(errno));
        fclose(handle);
        return 1;
    }

    if (fwrite(elf_header, sizeof(Elf32_Ehdr), 1, handle) != 1) {
        fprintf(stderr, "Failed to write updated ELF header to %s\n", argv[1]);
        fclose(handle);
        return 1;
    }

    fclose(handle);
    return 0;
}
