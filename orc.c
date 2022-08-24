#include <errno.h>
#include <string.h>
#include <endian.h>
#include <stdlib.h>

#include "orc.h"


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


enum ORCError calculate_file_offset(Elf32_Phdr *loadable_segs, Elf32_Half num_segs, Elf32_Addr vaddr, Elf32_Off *file_off) {
    for (Elf32_Half i = 0; i < num_segs; i++) {
        if (be32toh(loadable_segs[i].p_vaddr) < vaddr && vaddr < be32toh(loadable_segs[i].p_vaddr) + be32toh(loadable_segs[i].p_memsz)) {
            *file_off = htobe32((vaddr - be32toh(loadable_segs[i].p_vaddr)) + be32toh(loadable_segs[i].p_offset));
            fprintf(stderr, "0x%x\n", be32toh(*file_off));
            return ORC_SUCCESS;
        }
    }

    fprintf(stderr, "Failed to find loadable segment containing vaddr 0x%x\n", vaddr);
    return ORC_INVALID_ELF;
}


enum ORCError get_mips_stub_info(
    FILE *handle,
    Elf32_Word mips_external_gotno,
    Elf32_Off got_off,
    Elf32_Off dynsym_off,
    Elf32_Word got_entsize,
    Elf32_Word dynsym_entsize,
    Elf32_Word *stub_count,
    Elf32_Addr *stub_base_addr
) {
    Elf32_Sym sym;
    Elf32_Addr got_entry;
    *stub_base_addr = 0xffffffff;
    *stub_count = 0;

    for (Elf32_Word i = 0; i < mips_external_gotno; i++) {
        if (fseek(handle, dynsym_off + (i * dynsym_entsize), SEEK_SET) == -1) {
            fprintf(stderr, "Failed to seek to dynsym at offset 0x%x: %s\n", dynsym_off + (i * dynsym_entsize), strerror(errno));
            return ORC_FILE_IO_ERR;
        }
        if (fread(&sym, sizeof(Elf32_Sym), 1, handle) != 1)
        {
            if (ferror(handle)) {
                fprintf(stderr, "Failed to read dynamic symbol at offset 0x%x\n", dynsym_off + (i * dynsym_entsize));
                return ORC_FILE_IO_ERR;
            }
            fprintf(stderr, "Invalid dynsyms\n");
            return ORC_INVALID_ELF;
        }

        if (
            ELF32_ST_TYPE(sym.st_info) & STT_FUNC &&
            be16toh(sym.st_shndx) == SHN_UNDEF &&
            be32toh(sym.st_value) != 0
           ) {
            if (fseek(handle, got_off + (i * got_entsize), SEEK_SET) == -1) {
                fprintf(stderr, "Failed to seek to GOT at offset 0x%x: %s\n", got_off + (i * got_entsize), strerror(errno));
                return ORC_FILE_IO_ERR;
            }
            if (fread(&got_entry, sizeof(Elf32_Addr), 1, handle) != 1)
            {
                if (ferror(handle)) {
                    fprintf(stderr, "Failed to read GOT entry at offset 0x%x\n", got_off + (i * got_entsize));
                    return ORC_FILE_IO_ERR;
                }
                fprintf(stderr, "Invalid GOT\n");
                return ORC_INVALID_ELF;
            }

            if (sym.st_value == got_entry) {
                (*stub_count)++;
                if (be32toh(sym.st_value) < be32toh(*stub_base_addr))
                    *stub_base_addr = sym.st_value;
            }
        }
    }
    return ORC_SUCCESS;
}



/* https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-48031.html */
enum ORCError calculate_hash_size(FILE *handle, Elf32_Shdr *hash_section) {
    Elf32_Word nbucket, nchain;

    if (fseek(handle, be32toh(hash_section->sh_offset), SEEK_SET) == -1) {
        fprintf(stderr, "Failed to seek to hash at offset 0x%x: %s\n", be32toh(hash_section->sh_offset), strerror(errno));
        return ORC_FILE_IO_ERR;
    }

    if (fread(&nbucket, sizeof(Elf32_Word), 1, handle) != 1) {
        if (ferror(handle)) {
            fprintf(stderr, "Failed to read hash nbucket at offset 0x%x\n", be32toh(hash_section->sh_offset));
            return ORC_FILE_IO_ERR;
        }
        fprintf(stderr, "Invalid hash\n");
        return ORC_INVALID_ELF;
    }
    nbucket = be32toh(nbucket);
    fprintf(stderr, "hash nbucket: %u\n", nbucket);

    if (fread(&nchain, sizeof(Elf32_Word), 1, handle) != 1) {
        if (ferror(handle)) {
            fprintf(stderr, "Failed to read hash nchain at offset 0x%x\n", be32toh(hash_section->sh_offset) + 4);
            return ORC_FILE_IO_ERR;
        }
        fprintf(stderr, "Invalid hash\n");
        return ORC_INVALID_ELF;
    }
    nchain = be32toh(nchain);
    fprintf(stderr, "hash nchain: %u\n", nchain);

    hash_section->sh_size = htobe32(sizeof(Elf32_Word) * (2 + nchain + nbucket));
    return ORC_SUCCESS;
}


