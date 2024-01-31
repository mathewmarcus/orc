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

        dynamic_tag->d_tag = w2h(dynamic_tag->d_tag);
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

        if (ELF32_R_TYPE(w2h(rel.r_info)) == R_MIPS_JUMP_SLOT)
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
        if (w2h(phdr.p_type) == seg_type) {
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


enum ORCError find_vaddr_segment(Elf32_Phdr *loadable_segs, Elf32_Half num_segs, Elf32_Addr vaddr, Elf32_Half *segment_index) {
    for (Elf32_Half i = 0; i < num_segs; i++) {
        if (w2h(loadable_segs[i].p_vaddr) < vaddr && vaddr < w2h(loadable_segs[i].p_vaddr) + w2h(loadable_segs[i].p_memsz)) {
            *segment_index = i;
            return ORC_SUCCESS;
        }
    }

    fprintf(stderr, "Failed to find loadable segment containing vaddr 0x%x\n", vaddr);
    return ORC_INVALID_ELF;
}


enum ORCError calculate_file_offset(Elf32_Phdr *loadable_segs, Elf32_Half num_segs, Elf32_Addr vaddr, Elf32_Off *file_off) {
    enum ORCError err;
    Elf32_Half i;

    if ((err = find_vaddr_segment(loadable_segs, num_segs, vaddr, &i)) == ORC_SUCCESS)
        *file_off = h2w((vaddr - w2h(loadable_segs[i].p_vaddr)) + w2h(loadable_segs[i].p_offset));
    
    return err;
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
            s2h(sym.st_shndx) == SHN_UNDEF &&
            w2h(sym.st_value) != 0
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
                if (w2h(sym.st_value) < w2h(*stub_base_addr))
                    *stub_base_addr = sym.st_value;
            }
        }
    }
    return ORC_SUCCESS;
}



/* https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-48031.html */
enum ORCError calculate_hash_size(FILE *handle, Elf32_Shdr *hash_section) {
    Elf32_Word nbucket, nchain;

    if (fseek(handle, w2h(hash_section->sh_offset), SEEK_SET) == -1) {
        fprintf(stderr, "Failed to seek to hash at offset 0x%x: %s\n", w2h(hash_section->sh_offset), strerror(errno));
        return ORC_FILE_IO_ERR;
    }

    if (fread(&nbucket, sizeof(Elf32_Word), 1, handle) != 1) {
        if (ferror(handle)) {
            fprintf(stderr, "Failed to read hash nbucket at offset 0x%x\n", w2h(hash_section->sh_offset));
            return ORC_FILE_IO_ERR;
        }
        fprintf(stderr, "Invalid hash\n");
        return ORC_INVALID_ELF;
    }
    nbucket = w2h(nbucket);
    fprintf(stderr, "hash nbucket: %u\n", nbucket);

    if (fread(&nchain, sizeof(Elf32_Word), 1, handle) != 1) {
        if (ferror(handle)) {
            fprintf(stderr, "Failed to read hash nchain at offset 0x%x\n", w2h(hash_section->sh_offset) + 4);
            return ORC_FILE_IO_ERR;
        }
        fprintf(stderr, "Invalid hash\n");
        return ORC_INVALID_ELF;
    }
    nchain = w2h(nchain);
    fprintf(stderr, "hash nchain: %u\n", nchain);

    hash_section->sh_size = h2w(sizeof(Elf32_Word) * (2 + nchain + nbucket));
    return ORC_SUCCESS;
}

enum ORCError read_dynstr_table(FILE *handle, Elf32_Shdr *dynstr_sh, char **dynstr_table) {
    enum ORCError err;
    Elf32_Off dynstr_off = w2h(dynstr_sh->sh_offset);
    Elf32_Word dynstr_size = w2h(dynstr_sh->sh_size);

    if (!(*dynstr_table = malloc(dynstr_size))) {
        fprintf(stderr, "Failed to allocate %u bytes for dynamic string array: %s\n", dynstr_size, strerror(errno));
        return ORC_CRITICIAL;
    }

    if (fseek(handle, dynstr_off, SEEK_SET) == -1) {
        fprintf(stderr, "Failed to seek to dynamic string table at 0x%x: %s\n", dynstr_off, strerror(errno));
        return ORC_FILE_IO_ERR;
    }

    fprintf(stderr, "Attempting to read %u bytes of dynamic string table...\n", dynstr_size);
    if (fread(*dynstr_table, 1, dynstr_size, handle) != dynstr_size)
    {
        if (ferror(handle)) {
            fprintf(stderr, "Failed to read %u bytes of dynamic string table at 0x%x\n", dynstr_size, dynstr_off);
            return ORC_FILE_IO_ERR;
        }
        fprintf(stderr, "Invalid dynamic string table at 0x%x\n", dynstr_off);
        return ORC_INVALID_ELF;
    }
    fprintf(stderr, "Read %u bytes of dynamic string table\n", dynstr_size);

    return ORC_SUCCESS;
}


enum ORCError find_dynamic_symbol(FILE *handle, const char *sym_name, const int sym_type, const char *dynstr_table, const Elf32_Shdr *dynsym, Elf32_Sym *sym, Elf32_Word *sym_idx) {
    if (fseek(handle, w2h(dynsym->sh_offset), SEEK_SET) == -1) {
       fprintf(stderr, "Failed to seek to dynamic symbol table at 0x%x: %s\n", w2h(dynsym->sh_offset), strerror(errno));
       return ORC_CRITICIAL;
    }
    for (Elf32_Word i = 0; i < w2h(dynsym->sh_size); i += w2h(dynsym->sh_entsize)) {
        if (fread(sym, w2h(dynsym->sh_entsize), 1, handle) != 1)
        {
            if (ferror(handle)) {
                fprintf(stderr, "Failed to read symbol at index %hu\n", i);
                return ORC_FILE_IO_ERR;
            }
            fprintf(stderr, "Invalid dynamic symbol table\n");
            return ORC_INVALID_ELF;
        }
        
        if ((ELF32_ST_TYPE(sym->st_info) & sym_type) != sym_type)
            continue;

        if (!strcmp(sym_name, dynstr_table + w2h(sym->st_name))) {
            *sym_idx = i / w2h(dynsym->sh_entsize);
            fprintf(stderr, "Found dynamic symbol %s at index %u\n", sym_name, *sym_idx);
            return ORC_SUCCESS;
        }
    }
    fprintf(stderr, "Dynamic symbol %s not found\n", sym_name);
    return ORC_SYM_NOT_FOUND;

}


enum ORCError parse_rel_plt_from_dyn_seg(FILE *handle, Elf32_Off dyn_seg_offset, Elf32_Word dyn_seg_size, Elf32_Shdr *rel_plt) {
    Elf32_Dyn dynamic_tag;
    enum ORCError err;


    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_PLTREL, &dynamic_tag))) {
        case ORC_SUCCESS:
            if (w2h(dynamic_tag.d_un.d_val) != DT_REL) {
                fprintf(stderr, "DT_PLTREL has invalid value: %u; MIPS non-PIC ABI expect DT_REL (%u)\n", w2h(dynamic_tag.d_un.d_val), DT_REL);
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
            rel_plt->sh_entsize = dynamic_tag.d_un.d_val;
            fprintf(stderr, "Found DT_RELENT: %u\n", w2h(rel_plt->sh_entsize));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            /*
                Evidently some MIPS executables will not have a DT_RELENT tag
                if they don't have a DT_REL section
            */
            rel_plt->sh_entsize = h2w(sizeof(Elf32_Rel));
            fprintf(stderr, "Failed to find DT_RELENT dynamic tag, defaulting to sizeof(Elf32_rel) == %lu\n", sizeof(Elf32_Rel));
            break;
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_JMPREL, &dynamic_tag))) {
        case ORC_SUCCESS:
            rel_plt->sh_addr = dynamic_tag.d_un.d_ptr;
            fprintf(stderr, "Found DT_JMPREL: 0x%x\n", w2h(rel_plt->sh_addr));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_JMPREL dynamic tag\n");
        default:
            return err;
    }

    switch ((err = find_dynamic_tag(handle, dyn_seg_offset, dyn_seg_size, DT_PLTRELSZ, &dynamic_tag))) {
        case ORC_SUCCESS:
            rel_plt->sh_size = dynamic_tag.d_un.d_val;
            fprintf(stderr, "Found DT_PLTRELSZ: %u\n", w2h(rel_plt->sh_size));
            break;
        case ORC_DYN_TAG_NOT_FOUND:
            fprintf(stderr, "Failed to find DT_PLTRELSZ dynamic tag\n");
        default:
            return err;
    }

    return ORC_SUCCESS;
}


enum ORCError find_r_mips_jump_slot_rel(FILE *handle, Elf32_Shdr *rel_plt, Elf32_Word sym_idx, Elf32_Rel *rel, Elf32_Word *rel_idx) {
    if (fseek(handle, rel_plt->sh_offset, SEEK_SET) == -1) {
        fprintf(stderr, "Failed to seek to .rel.plt section at offset %u: %s\n", rel_plt->sh_offset, strerror(errno));
        return ORC_CRITICIAL;
    }
    fprintf(stderr, "Reading relocation in .rel.plt at offset 0x%x\n", rel_plt->sh_offset);

    for (Elf32_Word i = 0; i < rel_plt->sh_size; i += rel_plt->sh_entsize) {
        if (fread(rel, rel_plt->sh_entsize, 1, handle) != 1) {
            if (ferror(handle)) {
                fprintf(stderr, "Failed to read .rel.plt relocation %u\n", i/rel_plt->sh_entsize);
                return ORC_FILE_IO_ERR;
            }
            fprintf(stderr, "Invalid .rel.plt section\n");
            return ORC_INVALID_ELF;
        }

        if (ELF32_R_TYPE(w2h(rel->r_info)) == R_MIPS_JUMP_SLOT && ELF32_R_SYM(w2h(rel->r_info)) == sym_idx) {
            *rel_idx = i / rel_plt->sh_entsize;
            fprintf(stderr, "Found MIPS_JUMP_SLOT relocation %u for dynamic symbol %u\n", *rel_idx, sym_idx);
            return ORC_SUCCESS;
        }
    }

    return ORC_REL_NOT_FOUND;
}


/* https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html */
enum ORCError parse_gnu_version_requirements_size(FILE *handle, Elf32_Off offset, Elf32_Word verneednum, Elf32_Word *size) {
    Elf32_Verneed verneed;

    *size = verneednum * sizeof(Elf32_Verneed);

    while (verneednum--)
    {
        if (fseek(handle, offset, SEEK_SET) == -1) {
            fprintf(stderr, "Failed to seek to next verneed in .gnu.version_r section at offset %u: %s\n", offset, strerror(errno));
            return ORC_CRITICIAL;
        }
        if (fread(&verneed, sizeof(Elf32_Verneed), 1, handle) != 1) {
            if (ferror(handle)) {
                fprintf(stderr, "Failed to verneed in .gnu.version_r at offset\n");
                return ORC_FILE_IO_ERR;
            }
            fprintf(stderr, "Invalid .gnu.version_r section\n");
            return ORC_INVALID_ELF;
        }
        
        *size += s2h(verneed.vn_cnt) * sizeof(Elf32_Vernaux);
        offset = offset + w2h(verneed.vn_next);
    }

    *size = h2w(*size);
    return ORC_SUCCESS;

}

uint32_t h2be32(uint32_t val) {
    return htobe32(val);
}

uint32_t h2le32(uint32_t val) {
    return htole32(val);
}

uint32_t be322h(uint32_t val) {
    return be32toh(val);
}

uint32_t le322h(uint32_t val) {
    return le32toh(val);
}

uint16_t h2be16(uint16_t val) {
    return htobe16(val);
}

uint16_t h2le16(uint16_t val) {
    return htole16(val);
}

uint16_t be162h(uint16_t val) {
    return be16toh(val);
}

uint16_t le162h(uint16_t val) {
    return le16toh(val);
}