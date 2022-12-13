#pragma once

#include <cstdint>
#include <map>
#include <vector>

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
    uint64_t offset;
    uint64_t length;
    uint64_t compression; // 1 = uncompressed, 2 = compressed
    uint64_t encryption; // 1 = encrypted, 2 = plain
} segment_info_t;

typedef struct {
    uint64_t authid;                /* auth id */
    uint32_t vendor_id;             /* vendor id */
    uint32_t self_type;             /* app type 0x0D - , */
    uint64_t version;               /* app version */
    uint64_t padding;               /* UNKNOWN */
} app_info_t;

#define EI_NIDENT 16
#define EM_ARM (0x28)

enum phdr_flags : uint32_t {
    PF_X = 0x1,               // Execute
    PF_W = 0x2,               // Write
    PF_W_X = 0x3,             // Execute+Write
    PF_R = 0x4,               // Read
    PF_R_X = 0x5,             // Read, execute
    PF_R_W = 0x6,             // Read, write
    PF_R_W_X = 0x7,           // Read, write, execute
    PF_MASKOS = 0x0ff00000,   // Unspecified
    PF_MASKPROC = 0xf0000000, // Unspecified
};

typedef struct {
    unsigned char   e_ident[EI_NIDENT];
    Elf32_Half      e_type;
    Elf32_Half      e_machine;
    Elf32_Word      e_version;
    Elf32_Addr      e_entry;
    Elf32_Off       e_phoff;
    Elf32_Off       e_shoff;
    phdr_flags      e_flags;
    Elf32_Half      e_ehsize;
    Elf32_Half      e_phentsize;
    Elf32_Half      e_phnum;
    Elf32_Half      e_shentsize;
    Elf32_Half      e_shnum;
    Elf32_Half      e_shstrndx;
} elf_header_t;

#define PT_NULL (0x0U) // Unused entry - skip
#define PT_LOAD (0x1U) // Loadable segment
#define PT_SCE_RELA (0x60000000U) // Relocations
#define PT_SCE_COMMENT (0x6FFFFF00U) // Compiler signature?
#define PT_SCE_VERSION (0x6FFFFF01U) // SDK signature?
#define PT_ARM_EXIDX (0x70000001U)

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
} sce_rel;

typedef uint32_t Address;
struct SegmentInfoForReloc {
    std::vector<char> addr; // segment address in guest memory
    Address p_vaddr; // segment virtual address in guest memory
    uint64_t size; // segment memory size
};
using SegmentInfosForReloc = std::map<uint16_t, SegmentInfoForReloc>;

typedef struct sce_module_exports_t {
    uint16_t size;				/* Size of this struct, set to 0x20 */
    uint16_t version;			/* 0x1 for normal export, 0x0 for main module export */
    uint16_t flags;				/* 0x1 for normal export, 0x8000 for main module export */
    uint16_t num_syms_funcs;		/* Number of function exports */
    uint32_t num_syms_vars;			/* Number of variable exports */
    uint32_t num_syms_tls_vars;     /* Number of TLS variable exports */
    uint32_t library_nid;			/* NID of this library */
    uint32_t library_name;	/* Pointer to name of this library */
    uint32_t nid_table;		/* Pointer to array of 32-bit NIDs to export */
    uint32_t entry_table;	/* Pointer to array of data pointers for each NID */
};

typedef struct sce_module_imports_t {
    uint16_t size;				/* Size of this struct, set to 0x34 */
    uint16_t version;			/* Set to 0x1 */
    uint16_t flags;				/* Set to 0x0 */
    uint16_t num_syms_funcs;		/* Number of function imports */
    uint16_t num_syms_vars;			/* Number of variable imports */
    uint16_t num_syms_tls_vars;     /* Number of TLS variable imports */

    uint32_t reserved1;
    uint32_t library_nid;			/* NID of library to import */
    uint32_t library_name;	/* Pointer to name of imported library, for debugging */
    uint32_t reserved2;
    uint32_t func_nid_table;	/* Pointer to array of function NIDs to import */
    uint32_t func_entry_table;/* Pointer to array of stub functions to fill */
    uint32_t var_nid_table;	/* Pointer to array of variable NIDs to import */
    uint32_t var_entry_table;	/* Pointer to array of data pointers to write to */
    uint32_t tls_var_nid_table; /* Pointer to array of TLS variable NIDs to import */
    uint32_t tls_var_entry_table; /* Pointer to array of data pointers to write to */
};

typedef struct sce_module_info_t { // size is 0x5C-bytes
    uint16_t attributes;
    uint16_t version;			/* Set to 0x0101 */
    char name[27];				/* Name of the library */
    uint8_t type;				/* 0x0 for executable, 0x6 for PRX */
    uint32_t gp_value;
    uint32_t export_top;			/* Offset to start of export table */
    uint32_t export_end;			/* Offset to end of export table */
    uint32_t import_top;			/* Offset to start of import table */
    uint32_t import_end;			/* Offset to end of import table */
    uint32_t module_nid;			/* NID of this module */
    uint32_t tls_start;
    uint32_t tls_filesz;
    uint32_t tls_memsz;
    uint32_t module_start;	/* Offset to function to run when library is started, 0 to disable */
    uint32_t module_stop;	/* Offset to function to run when library is exiting, 0 to disable */
    uint32_t exidx_top;	/* Offset to start of ARM EXIDX (optional) */
    uint32_t exidx_end;	/* Offset to end of ARM EXIDX (optional) */
    uint32_t extab_top;	/* Offset to start of ARM EXTAB (optional) */
    uint32_t extab_end;	/* Offset to end of ARM EXTAB (optional */
};