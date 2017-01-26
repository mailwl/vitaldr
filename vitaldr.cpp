#define _CRT_SECURE_NO_WARNINGS

#include "vitaldr.h"

#ifdef _CONSOLE

#include <stdio.h>
#include <string.h>

#define linput_t FILE
#define MAX_FILE_FORMAT_NAME 256
#define idaapi
#define SETPROC_ALL 1
#define SETPROC_FATAL 2
#define ACCEPT_FIRST 4

static uint32_t qlsize(linput_t* li) {
    fseek(li, 0, SEEK_END);
    uint32_t size = ftell(li);
    fseek(li, 0, SEEK_SET);
    return size;
}

static char file_type[MAX_FILE_FORMAT_NAME];

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

#else
#include "idaldr.h"
#pragma comment(lib, "ida")
#endif

static self_header_t self_header;
static app_info_t app_info;
static elf_header_t elf_header_fake, elf_header;

void load_header(linput_t* li) {
    qlseek(li, 0);
    qlread(li, &self_header, sizeof self_header_t);
    qlseek(li, static_cast<uint32_t>(self_header.appinfo_offset));
    qlread(li, &app_info, sizeof app_info_t);
    qlseek(li, static_cast<uint32_t>(self_header.elf_offset));
    qlread(li, &elf_header_fake, sizeof elf_header_t);
    qlseek(li, static_cast<uint32_t>(self_header.header_len));
}

int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n) {
    if (n != 0) {
        return 0;
    }

    load_header(li);

    if((self_header.magic == 0x00454353) && (self_header.version == 3)) {
        // TODO: check if prx
        qstrncpy(fileformatname, "Sony Playstation Vita eboot.bin", MAX_FILE_FORMAT_NAME);
        set_processor_type("ARM", SETPROC_ALL|SETPROC_FATAL);
        return 1 | ACCEPT_FIRST;
    }
    return 0;
}

void idaapi load_file(linput_t *li, uint16_t neflags, const char *fileformatname) {
    load_header(li);
    qlseek(li, static_cast<uint32_t>(self_header.header_len));

    qlread(li, &elf_header, sizeof elf_header_t);

}


#ifdef _CONSOLE
int main(int argc, char* argv[]) {
    if (argc == 2) {
        // linput_t* li = fopen("D:\\distrib\\siscontents\\1\\2\\extetra\\eboot.bin", "rb");
        linput_t* li = fopen(argv[1], "rb");
        if (li) {

            if (accept_file(li, file_type, 0)) {
                load_file(li, 0, file_type);
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

loader_t LDSC {
    IDP_INTERFACE_VERSION,
    0,
    accept_file,
    load_file,
    NULL,
    NULL,
    NULL
};
#endif
