#pragma once

#include <stdint.h>

typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Off;
typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;

typedef struct {
  uint32_t magic;                 /* 53434500 = SCE\0 */
  uint32_t version;               /* header version 3*/
  uint16_t sdk_type;              /* */
  uint16_t header_type;           /* 1 self, 2 unknown, 3 pkg */
  uint32_t metadata_offset;       /* metadata offset */
  uint64_t header_len;            /* self header length */
  uint64_t elf_filesize;          /* ELF file length */
  uint64_t self_filesize;         /* SELF file length */
  uint64_t unknown;               /* UNKNOWN */
  uint64_t self_offset;           /* SELF offset */
  uint64_t appinfo_offset;        /* app info offset */
  uint64_t elf_offset;            /* ELF #1 offset */
  uint64_t phdr_offset;           /* program header offset */
  uint64_t shdr_offset;           /* section header offset */
  uint64_t section_info_offset;   /* section info offset */
  uint64_t sceversion_offset;     /* version offset */
  uint64_t controlinfo_offset;    /* control info offset */
  uint64_t controlinfo_size;      /* control info size */
  uint64_t padding;               
} self_header_t;

typedef struct {
  uint64_t authid;                /* auth id */
  uint32_t vendor_id;             /* vendor id */
  uint32_t self_type;             /* app type 0x0D - , */
  uint64_t version;               /* app version */
  uint64_t padding;               /* UNKNOWN */
} app_info_t;

#define EI_NIDENT 16

typedef struct {
    unsigned char   e_ident[EI_NIDENT];
    Elf32_Half      e_type;
    Elf32_Half      e_machine;
    Elf32_Word      e_version;
    Elf32_Addr      e_entry;
    Elf32_Off       e_phoff;
    Elf32_Off       e_shoff;
    Elf32_Word      e_flags;
    Elf32_Half      e_ehsize;
    Elf32_Half      e_phentsize;
    Elf32_Half      e_phnum;
    Elf32_Half      e_shentsize;
    Elf32_Half      e_shnum;
    Elf32_Half      e_shstrndx;
} elf_header_t;

typedef struct {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
} elf_phdr_t;

typedef union {
    Elf32_Word r_short : 4;
    struct {
        Elf32_Word r_short     : 4;
        Elf32_Word r_symseg    : 4;
        Elf32_Word r_code      : 8;
        Elf32_Word r_datseg    : 4;
        Elf32_Word r_offset_lo : 12;
        Elf32_Word r_offset_hi : 20;
        Elf32_Word r_addend    : 12;
    } r_short_entry;
    struct {
        Elf32_Word r_short     : 4;
        Elf32_Word r_symseg    : 4;
        Elf32_Word r_code      : 8;
        Elf32_Word r_datseg    : 4;
        Elf32_Word r_code2     : 8;
        Elf32_Word r_dist2     : 4;
        Elf32_Word r_addend;
        Elf32_Word r_offset;
    } r_long_entry;
    struct {
        Elf32_Word r_word1;
        Elf32_Word r_word2;
        Elf32_Word r_word3;
    } r_raw_entry;
} SCE_Rel;

