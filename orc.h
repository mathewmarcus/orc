#ifndef ORC_H
#define ORC_H

#include <stdio.h>
#include <elf.h>

#define IS_SUPPORTED_ARCH(elf_hdr) (elf_hdr->e_ident[EI_CLASS] & ELFCLASS32 && elf_hdr->e_ident[EI_DATA] & ELFDATA2MSB && be16toh(elf_hdr->e_machine) == EM_MIPS)
#define IS_MIPS_NONPIC(elf_hdr) (elf_hdr->e_ident[EI_ABIVERSION] == 0x1 && (htobe32(elf_hdr->e_flags) & EF_MIPS_CPIC) && !(htobe32(elf_hdr->e_flags) & EF_MIPS_PIC))

enum ORCError {
    ORC_SUCCESS,
    ORC_CRITICIAL,
    ORC_FILE_IO_ERR,
    ORC_INVALID_ELF,
    ORC_DYN_TAG_NOT_FOUND,
    ORC_DYN_VALUE_INVALID,
    ORC_PHDR_NOT_FOUND,
    ORC_SYM_NOT_FOUND
};


enum ORCError find_dynamic_tag(FILE *handle, Elf32_Off dyn_seg_offset, Elf32_Word dyn_seg_size, Elf32_Sword tag, Elf32_Dyn *dynamic_tag);
enum ORCError count_mips_jump_slot_relocs(FILE *handle, Elf32_Off rel_plt_offset, Elf32_Word rel_plt_size, Elf32_Word *count);
enum ORCError find_program_headers(FILE *handle, Elf32_Off ph_off, Elf32_Half ph_num, Elf32_Word seg_type, Elf32_Phdr **phdrs, Elf32_Half *count);
enum ORCError calculate_file_offset(Elf32_Phdr *loadable_segs, Elf32_Half num_segs, Elf32_Addr vaddr, Elf32_Off *file_off);
enum ORCError get_mips_stub_info(
    FILE *handle,
    Elf32_Word mips_external_gotno,
    Elf32_Off got_off,
    Elf32_Off dynsym_off,
    Elf32_Word got_entsize,
    Elf32_Word dynsym_entsize,
    Elf32_Word *stub_count,
    Elf32_Addr *stub_base_addr
);
enum ORCError calculate_hash_size(FILE *handle, Elf32_Shdr *hash_section);
enum ORCError read_dynstr_table(FILE *handle, Elf32_Phdr *dyn_seg, Elf32_Phdr *loadable_segs, Elf32_Half num_segs, char **dynstr_table);
enum ORCError find_dynamic_symbol(FILE *handle, const char *sym_name, const char *dynstr_table, const Elf32_Shdr *dynsym, Elf32_Sym *sym, Elf32_Word *sym_idx);
enum ORCError parse_rel_plt_from_dyn_seg(FILE *handle, Elf32_Off dyn_seg_offset, Elf32_Word dyn_seg_size, Elf32_Shdr *rel_plt);

#endif