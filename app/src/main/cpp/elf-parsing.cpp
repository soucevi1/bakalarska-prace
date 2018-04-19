/*
 * Tento kod je soucast bakalarske prace Aplikace vyuzivajici zranitelnost Dirty Cow pro operacni system Android
 * Autor: Vit Soucek (soucevi1@fit.cvut.cz)
 * Zdroj: Parser ELF souboru uzivatele GitHubu eklitzke (https://github.com/eklitzke/parse-elf)
 *          - upraveno tak, aby program hledal pouze adresu __vdso_clock_gettime, popr. __kernel_clock_gettime
 *          - pridana podpora 32bitovych ELFu
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <android/log.h>

#include <cassert>
#include <cstdio>
#include <cstring>

#include <iostream>

#define APPNAME "DIRTY_COW"
#define LOG(...) { __android_log_print(ANDROID_LOG_ERROR, APPNAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); }

// Pojmenovani architektur
enum architectures{e64, e32};

unsigned long parse_elf_32_bit(void *address){
    const unsigned char expected_magic[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
    Elf32_Ehdr elf_header;
    memmove(&elf_header, address, sizeof(elf_header));
    if (memcmp(elf_header.e_ident, expected_magic, sizeof(expected_magic)) != 0) {
        LOG("Target is not an ELF executable");
        return 0;
    }

    char *cbytes = (char *)address;

    size_t dynstr_off = 0;
    size_t dynsym_off = 0;
    size_t dynsym_sz = 0;

    for (uint16_t i = 0; i < elf_header.e_shnum; i++) {
        size_t offset = elf_header.e_shoff + i * elf_header.e_shentsize;
        Elf32_Shdr shdr;
        memmove(&shdr, (void*)((unsigned long)(address) + offset), sizeof(shdr));
        switch (shdr.sh_type) {
            case SHT_SYMTAB:
            case SHT_STRTAB:
                if (!dynstr_off) {
                    dynstr_off = shdr.sh_offset;
                }
                break;
            case SHT_DYNSYM:
                dynsym_off = shdr.sh_offset;
                dynsym_sz = shdr.sh_size;
                break;
            default:
                break;
        }
    }
    assert(dynstr_off);
    assert(dynsym_off);

    unsigned long clock_gettime_offset = 0;

    for (size_t j = 0; j * sizeof(Elf32_Sym) < dynsym_sz; j++) {
        Elf32_Sym sym;
        size_t absoffset = dynsym_off + j * sizeof(Elf32_Sym);
        memmove(&sym, cbytes + absoffset, sizeof(sym));
        if (sym.st_name != 0) {
            if (strcmp(cbytes + dynstr_off + sym.st_name, "__vdso_clock_gettime") == 0) {
                clock_gettime_offset = (unsigned long) sym.st_value;
                break;
            }
            if (strcmp(cbytes + dynstr_off + sym.st_name, "__kernel_clock_gettime") == 0) {
                clock_gettime_offset = (unsigned long) sym.st_value;
                break;
            }
        }
    }

    return clock_gettime_offset;
}

unsigned long parse_elf_64_bit(void *address){
    const unsigned char expected_magic[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
    Elf64_Ehdr elf_header;
    memmove(&elf_header, address, sizeof(elf_header));
    if (memcmp(elf_header.e_ident, expected_magic, sizeof(expected_magic)) != 0) {
        LOG("Target is not an ELF executable");
        return 0;
    }

    char *cbytes = (char *)address;

    size_t dynstr_off = 0;
    size_t dynsym_off = 0;
    size_t dynsym_sz = 0;

    for (uint16_t i = 0; i < elf_header.e_shnum; i++) {
        size_t offset = elf_header.e_shoff + i * elf_header.e_shentsize;
        Elf64_Shdr shdr;
        memmove(&shdr, (void*)((unsigned long)(address) + offset), sizeof(shdr));
        switch (shdr.sh_type) {
            case SHT_SYMTAB:
            case SHT_STRTAB:
                if (!dynstr_off) {
                    dynstr_off = shdr.sh_offset;
                }
                break;
            case SHT_DYNSYM:
                dynsym_off = shdr.sh_offset;
                dynsym_sz = shdr.sh_size;
                break;
            default:
                break;
        }
    }
    assert(dynstr_off);
    assert(dynsym_off);

    unsigned long clock_gettime_offset = 0;

    for (size_t j = 0; j * sizeof(Elf64_Sym) < dynsym_sz; j++) {
        Elf64_Sym sym;
        size_t absoffset = dynsym_off + j * sizeof(Elf64_Sym);
        memmove(&sym, cbytes + absoffset, sizeof(sym));
        if (sym.st_name != 0) {
            if(strcmp(cbytes + dynstr_off + sym.st_name, "__vdso_clock_gettime") == 0){
                clock_gettime_offset = (unsigned long)sym.st_value;
                break;
            }
            if(strcmp(cbytes + dynstr_off + sym.st_name, "__kernel_clock_gettime") == 0){
                clock_gettime_offset = (unsigned long)sym.st_value;
                break;
            }
        }
    }
    return clock_gettime_offset;
}

unsigned long get_offset_from_elf(void *address, int architecture) {

    unsigned long offset = 0;
    switch(architecture){
        case e64:
        LOG("    Parsing 64bit ELF");
            offset = parse_elf_64_bit(address);
            LOG("    - offset parsed: %lx", offset);
            break;

        case e32:
        LOG("    Parsing 32bit ELF")
            offset = parse_elf_32_bit(address);
            LOG("    - offset parsed: %lx", offset);
            break;

        default:
        LOG("    Architecture not supported");
            break;

    }
    return offset;
}