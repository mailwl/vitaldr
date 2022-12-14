
#include "vitaldr.h"
#include "nids_resolver.h"
#include "miniz.h"

#undef _CONSOLE

#ifdef _CONSOLE

#include <stdio.h>
#include <string.h>
#include <string>

typedef std::string qstring;
#define linput_t FILE
#define MAX_FILE_FORMAT_NAME 256
#define idaapi
#define SETPROC_ALL 1
#define SETPROC_FATAL 2
#define ACCEPT_FIRST 4
#define FILEREG_PATCHABLE 1
#define NAME_CODE ".code"
#define CLASS_CODE "CODE"
#define NAME_DATA ".data"
#define CLASS_DATA "DATA"

#define SETPROC_LOADER 1

#define qsnprintf snprintf 
#define msg printf
#define qchar char

typedef uint64_t qoff64_t;
typedef uint32_t ea_t;
typedef void* segment_t;

static uint32_t qlsize(linput_t* li) {
    fseek(li, 0, SEEK_END);
    uint32_t size = ftell(li);
    fseek(li, 0, SEEK_SET);
    return size;
}

static void qlseek(linput_t* li, uint32_t offset, int whence=SEEK_SET) {
    fseek(li, offset, whence);
}

static uint32_t qlread(linput_t* li, void* buffer, uint32_t size) {
    return fread(buffer, size, 1, li);
}

static char* qstrncpy(char* dest, const char* src, uint32_t size) {
    return strncpy(dest, src, size);
}

static void set_processor_type(const char*, uint32_t) {
    // nothing to do
}

int file2base(linput_t* li, qoff64_t pos, ea_t ea1, ea_t ea2, int patchable) {
    return 1;
}

bool add_segm(ea_t para, ea_t start, ea_t end, const char* name, const char* sclass, int flags = 0) {
    return true;
}

void loader_failure() {
}

segment_t* getseg(ea_t) {
    return nullptr;
}

void set_segm_addressing(segment_t* s, int) {
}

void create_filename_cmt() {
}

void add_entry(ea_t, ea_t, const char*, bool makecode, int flags = 0) {

}

int mem2base(const void* memptr, ea_t ea1, ea_t ea2, qoff64_t fpos) {
    return 1;
}

bool append_cmt(ea_t ea, const char* str, bool rptble) {
    return true;
}

void set_cmt(ea_t, const char*, bool) {

}

void set_name(ea_t, const char*, int flags = 0) {

}

void set_processor_type(const char*, int) {

}

#else
#include <idaldr.h>
#include <segment.hpp>
#pragma comment(lib, "ida")
#endif

/*
static self_header_t self_header;
static app_info_t app_info;
static elf_header_t  elf_header;
static std::vector<elf_phdr_t> program_headers;
static std::vector<segment_info_t> seg_infos;
*/
static SegmentInfosForReloc segment_reloc_info;


extern "C"
int idaapi accept_file(qstring *fileformatname, qstring *processor, linput_t *li, const char *filename) {
    
    self_header_t self_header;
    elf_header_t  elf_header;
    qlseek(li, 0);
    qlread(li, &self_header, sizeof self_header_t);
    qlseek(li, static_cast<uint32_t>(self_header.elf_offset));
    qlread(li, &elf_header, sizeof elf_header_t);

    bool test = (self_header.magic == 0x00454353) && (self_header.version == 3);
    if (!test) return 0;

    test = (elf_header.e_machine == EM_ARM);

    if (!test) return 0;
    

    *fileformatname = "Sony Playstation Vita eboot.bin";
    *processor = "arm";

    return 1 | ACCEPT_FIRST;
}
extern "C"
void idaapi load_file(linput_t *li, uint16_t neflags, const char *fileformatname) {

    // read content of file
    uint32_t size = qlsize(li);
    std::vector<uint8_t> buf(size);
    qlseek(li, 0);
    qlread(li, buf.data(), size);

    self_header_t self_header;
    elf_header_t  elf_header;
    std::memcpy(&self_header, buf.data(), sizeof self_header_t);
    std::memcpy(&elf_header, buf.data() + self_header.elf_offset, sizeof elf_header_t);
    const segment_info_t* seg_info = reinterpret_cast<const segment_info_t*>(buf.data() + self_header.section_info_offset);
    const elf_phdr_t* phdr = reinterpret_cast<const elf_phdr_t*>(buf.data() + self_header.phdr_offset);

    bool is_relocatable{ false };
    if (elf_header.e_type == ET_SCE_EXEC) {
        is_relocatable = false;
    }
    else if (elf_header.e_type == ET_SCE_RELEXEC) {
        is_relocatable = true;
    }

    for (uint32_t i = 0; i < elf_header.e_phnum; ++i) {
        std::vector<uint8_t> segment;
        if (phdr->p_type == PT_LOAD) {
            if (seg_info->compression == 2) {
                // decompress
                unsigned long dest_bytes = phdr->p_filesz;
                const uint8_t* const compressed_segment_bytes = buf.data() + seg_info->offset;
                segment.resize(dest_bytes);
                int res = mz_uncompress(segment.data(), &dest_bytes, compressed_segment_bytes, static_cast<mz_ulong>(seg_info->length));
                assert(res == MZ_OK);
            }
            else {
                segment.resize(phdr->p_filesz);
                uint32_t begin = phdr->p_offset + self_header.header_len;
                uint32_t end = begin + phdr->p_filesz;
                std::copy(buf.cbegin() + begin, buf.cbegin() + end, segment.begin());
            }
            mem2base(segment.data(), phdr->p_vaddr, phdr->p_vaddr + phdr->p_filesz, phdr->p_offset + self_header.header_len);
            segment_reloc_info[i] = { std::move(segment), phdr->p_vaddr, phdr->p_memsz };

            bool is_code = (PF_X & phdr->p_flags) == PF_X;

            if (!add_segm(0, phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz, is_code ? NAME_CODE : NAME_DATA, is_code ? CLASS_CODE : CLASS_DATA)) {
                loader_failure();
            }
            segment_t* s = getseg(phdr->p_vaddr);
            set_segm_addressing(s, 1);
        }
        else if (phdr->p_type == PT_SCE_RELA) {
            // TODO: relocate?
        }

        seg_info++;
        phdr++;
    }

    const uint32_t module_info_offset = elf_header.e_entry & 0x3fffffff;
    const uint32_t module_info_segment_index = static_cast<uint32_t>(elf_header.e_entry >> 30);
    const char* module_info_segment_bytes = (const char*)(segment_reloc_info[module_info_segment_index].addr.data());
    const sce_module_info_t* const module_info = reinterpret_cast<const sce_module_info_t*>(module_info_segment_bytes + module_info_offset);

    const sce_module_exports_t* exports = reinterpret_cast<const sce_module_exports_t*>(module_info_segment_bytes + module_info->export_top);
    

    uint32_t exports_count = (module_info->export_end - module_info->export_top) / sizeof(sce_module_exports_t);
    uint32_t imports_count = (module_info->import_end - module_info->import_top) / sizeof(sce_module_imports_t);

    uint32_t p_vaddr = segment_reloc_info[module_info_segment_index].p_vaddr;

    for (uint32_t i = 0; i < exports_count; ++i) {
        // TODO: set adresses to IDA
        const char* lib_name = module_info->name;
        if (lib_name != nullptr) {
            msg("exports from library: %s\n", lib_name);
        }
        const uint32_t* func_nids = reinterpret_cast<const uint32_t*>(module_info_segment_bytes + (exports->nid_table - p_vaddr));
        const uint32_t* func_entry = reinterpret_cast<const uint32_t*>(module_info_segment_bytes + (exports->entry_table - p_vaddr));
        for (uint32_t j = 0; j < exports->num_syms_funcs; ++j) {
            if (lib_name != nullptr) {
                auto name = resolve(lib_name, func_nids[j]);
                const char* fname = name.c_str();
                msg("  export nid: 0x%x, entry: 0x%x, name: %s\n", func_nids[j], func_entry[j], fname);
                set_cmt(func_entry[j] & ~1, lib_name, false);
                set_name(func_entry[j] & ~1, fname);
            }
        }
        exports = reinterpret_cast<const sce_module_exports_t*>((const uint8_t*)exports + exports->size);
    }
    
    const uint16_t* import_size = reinterpret_cast<const uint16_t*>(module_info_segment_bytes + module_info->import_top);
    
    if (*import_size == 0x34) { // version 1
        const sce_module_imports_t* imports = reinterpret_cast<const sce_module_imports_t*>(module_info_segment_bytes + module_info->import_top);
        for (uint32_t i = 0; i < imports_count; ++i) {
            const char* lib_name = module_info_segment_bytes + (imports->library_name - p_vaddr);

            msg("imports from library: %s\n", lib_name);

            const uint32_t* func_nids = reinterpret_cast<const uint32_t*>(module_info_segment_bytes + (imports->func_nid_table - p_vaddr));
            const uint32_t* func_entry = reinterpret_cast<const uint32_t*>(module_info_segment_bytes + (imports->func_entry_table - p_vaddr));
            for (uint32_t j = 0; j < imports->num_syms_funcs; ++j) {
                auto name = resolve(lib_name, func_nids[j]);
                const char* fname = name.c_str();
                msg("  import nid: 0x%x, entry: 0x%x, name: %s\n", func_nids[j], func_entry[j], fname);
                set_cmt(func_entry[j] & ~1, lib_name, false);
                set_name(func_entry[j] & ~1, fname);
            }
            imports = reinterpret_cast<const sce_module_imports_t*>((const uint8_t*)imports + imports->size);
        }
    }
    else { // version 2
        const sce_module_imports_small_t* imports = reinterpret_cast<const sce_module_imports_small_t*>(module_info_segment_bytes + module_info->import_top);
        for (uint32_t i = 0; i < imports_count; ++i) {
            const char* lib_name = module_info_segment_bytes + (imports->library_name - p_vaddr);

            msg("imports from library: %s\n", lib_name);

            const uint32_t* func_nids = reinterpret_cast<const uint32_t*>(module_info_segment_bytes + (imports->func_nid_table - p_vaddr));
            const uint32_t* func_entry = reinterpret_cast<const uint32_t*>(module_info_segment_bytes + (imports->func_entry_table - p_vaddr));
            for (uint32_t j = 0; j < imports->num_syms_funcs; ++j) {
                auto name = resolve(lib_name, func_nids[j]);
                const char* fname = name.c_str();
                msg("  import nid: 0x%x, entry: 0x%x, name: %s\n", func_nids[j], func_entry[j], fname);
                set_cmt(func_entry[j] & ~1, lib_name, false);
                set_name(func_entry[j] & ~1, fname);
            }

            imports = reinterpret_cast<const sce_module_imports_small_t*>((const uint8_t*)imports + imports->size);
        }
        msg("unsupported import header size: 0x%x", *import_size);


    }
#ifndef _CONSOLE
    if (!(module_info->module_start == 0 || module_info->module_start == -1)) {
        uint32_t entry = p_vaddr + (module_info->module_start /* & ~1*/);
        add_entry(entry, entry, nullptr, true);
        inf.start_ea = entry;
        //inf.start_ip = entry + 0x10;
        inf.demnames |= DEMNAM_GCC3;
    }
#endif
    set_processor_type("ARM", SETPROC_LOADER);
    create_filename_cmt();
}


#ifdef _CONSOLE
int main(int argc, char* argv[]) {
    if (argc == 2) {
        linput_t* li = fopen(argv[1], "rb");
        if (li) {
            qstring fileformatname, processor;
            if (accept_file(&fileformatname, &processor, li, argv[1])) {
                load_file(li, 0, fileformatname.c_str());
            }
            fclose(li);
        }
        return 0;
    }
    return -1;
}
#else
// TODO add IDA stuff
#include <windows.h>
bool APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    default: 
        break;
    }
    return true;
}

extern "C"
loader_t LDSC{
    IDP_INTERFACE_VERSION,
    0,
    accept_file,
    load_file,
    nullptr,
    nullptr,
    nullptr,
};
#endif
