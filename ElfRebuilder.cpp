//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/4.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
#include <c++/cstdio>
#include "ElfRebuilder.h"
#include "elf.h"

ElfRebuilder::ElfRebuilder(ElfReader *elf_reader) {
    elf_reader_ = elf_reader;
}

bool ElfRebuilder::RebuildPhdr() {
    auto phdr = (Elf_Phdr*)elf_reader_->loaded_phdr();
    for(auto i = 0; i < elf_reader_->phdr_count(); i++) {
        phdr->p_filesz = phdr->p_memsz;     // expend filesize to memsiz
        // p_paddr and p_align is not used in load, just ignore it.
        // fix file offset.
        phdr->p_paddr = phdr->p_vaddr;
        phdr->p_offset = phdr->p_vaddr;     // elf has been loaded.
        phdr++;
    }
    return true;
}

bool ElfRebuilder::RebuildShdr() {
    // rebuilding shdr, link information
    auto base = si.load_bias;
    shstrtab.push_back('\0');

    // empty shdr
    if(true) {
        Elf_Shdr shdr = {0};
        shdrs.push_back(shdr);
    }

    // gen .dynsym
    if(si.symtab != nullptr) {
        sDYNSYM = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynsym");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNSYM;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (Elf_Addr)si.symtab - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;   // calc sh_size later(pad to next shdr)
        shdr.sh_link = 0;   // link to dynstr later
        shdr.sh_info = 1;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x10;

        shdrs.push_back(shdr);
    }

    // gen .dynstr
    if(si.strtab != nullptr) {
        sDYNSTR = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynstr");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_STRTAB;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (Elf_Addr)si.strtab - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.strtabsize;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .hash
    if(si.hash != 0) {
        sHASH = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".hash");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_HASH;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = si.hash - base;
        shdr.sh_offset = shdr.sh_addr;
        // TODO 32bit, 64bit?
        shdr.sh_size = (si.nbucket + si.nchain) * sizeof(Elf_Addr) + 2 * sizeof(Elf_Addr);
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x4;

        shdrs.push_back(shdr);
    }

    // gen .rel.dyn
    if(si.rel != nullptr) {
        sRELDYN = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rel.dyn");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_REL;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (Elf_Addr)si.rel - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.rel_count * sizeof(Elf_Rel);
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;

        shdrs.push_back(shdr);
    }

    // gen .rel.plt
    if(si.plt_rel != nullptr) {
        sRELPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rel.plt");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_REL;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (Elf_Addr)si.plt_rel - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.plt_rel_count * sizeof(Elf_Rel);
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;

        shdrs.push_back(shdr);
    }

    // gen.plt with .rel.plt
    if(si.plt_rel != nullptr) {
        sPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".plt");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr = shdrs[sRELPLT].sh_addr + shdrs[sRELPLT].sh_size;
        shdr.sh_offset = shdr.sh_addr;
        // TODO fix size 32bit 64bit?
        shdr.sh_size = 20/*Pure code*/ + 12 * si.plt_rel_count;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen.text&ARM.extab
    if(si.plt_rel != nullptr) {
        sTEXTTAB = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".text&ARM.extab");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr =  shdrs[sPLT].sh_addr + shdrs[sPLT].sh_size;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;       // calc later
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen ARM.exidx
    if(si.ARM_exidx != nullptr) {
        sARMEXIDX = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".ARM.exidx");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_ARMEXIDX;
        shdr.sh_flags = SHF_ALLOC | SHF_LINK_ORDER;
        shdr.sh_addr = (Elf_Addr)si.ARM_exidx - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.ARM_exidx_count * sizeof(Elf_Addr);
        shdr.sh_link = sTEXTTAB;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;

        shdrs.push_back(shdr);
    }
    // gen .fini_array
    if(si.fini_array != nullptr) {
        sRELPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".fini_array");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_FINI_ARRAY;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (Elf_Addr)si.fini_array - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.fini_array_count * sizeof(Elf_Addr);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .init_array
    if(si.init_array != nullptr) {
        sRELPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".init_array");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_INIT_ARRAY;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (Elf_Addr)si.init_array - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.init_array_count * sizeof(Elf_Addr);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .dynamic
    if(si.dynamic != nullptr) {
        sDYNAMIC = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynamic");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNAMIC;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (Elf_Addr)si.dynamic - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.dynamic_count * sizeof(Elf_Dyn);
        shdr.sh_link = sDYNSTR;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;

        shdrs.push_back(shdr);
    }

    // get .got
    if(si.plt_got != nullptr) {
        // global_offset_table
        sGOT = shdrs.size();
        auto sLast = sGOT - 1;

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".got");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = shdrs[sLast].sh_addr + shdrs[sLast].sh_size;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = (Elf_Addr)(si.plt_got + si.plt_rel_count) - shdr.sh_addr;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .data
    if(true) {
        sDATA = shdrs.size();
        auto sLast = sDATA - 1;

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".data");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = shdrs[sLast].sh_addr + shdrs[sLast].sh_size;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.max_load - shdr.sh_addr;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .bss
    if(true) {
        sBSS = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".bss");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_NOBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = si.max_load;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;   // not used
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .shstrtab, pad into last data
    if(true) {
        sSHSTRTAB = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".shstrtab");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_STRTAB;
        shdr.sh_flags = 0;
        shdr.sh_addr = si.max_load;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = shstrtab.length();
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // link section data
    if(sDYNSYM != 0) {
        shdrs[sDYNSYM].sh_link = sDYNSTR;
        auto sNext = sDYNSYM + 1;
        shdrs[sDYNSYM].sh_size = shdrs[sNext].sh_addr - shdrs[sDYNSYM].sh_addr;
    }

    if(sTEXTTAB != 0) {
        auto sNext = sDYNSYM + 1;
        shdrs[sTEXTTAB].sh_size = shdrs[sNext].sh_addr - shdrs[sTEXTTAB].sh_addr;
    }

    // TODO fuck relloc in dump
//    if (si.plt_rel != NULL) {
//        DEBUG("[ relocating %s plt ]", si->name );
//        if (soinfo_relocate(si, si->plt_rel, si->plt_rel_count, needed)) {
//            return false;
//        }
//    }
//    if (si.rel != NULL) {
//        DEBUG("[ relocating %s ]", si->name );
//        if (soinfo_relocate(si, si->rel, si->rel_count, needed)) {
//            return false;
//        }
//    }

#ifdef ANDROID_MIPS_LINKER
    if (!mips_relocate_got(si, needed)) {
        return false;
    }
#endif

//    for(;i < ph_num;i++) {
//        if (phdr[i].p_type == PT_LOAD) {
//            if (phdr[i].p_vaddr > 0x0) {
//                load = phdr[i];
//                shdr[BSS].sh_name = strstr(str,".bss") - str;
//                shdr[BSS].sh_type = SHT_NOBITS;
//                shdr[BSS].sh_flags = SHF_WRITE | SHF_ALLOC;
//                shdr[BSS].sh_addr =  phdr[i].p_vaddr + phdr[i].p_filesz;
//                shdr[BSS].sh_offset = shdr[BSS].sh_addr - 0x1000;
//                shdr[BSS].sh_addralign = 1;
//                continue;
//            }
//        }
//
//        if(phdr[i].p_type == PT_DYNAMIC) {
//            shdr[DYNAMIC].sh_name = strstr(str, ".dynamic") - str;
//            shdr[DYNAMIC].sh_type = SHT_DYNAMIC;
//            shdr[DYNAMIC].sh_flags = SHF_WRITE | SHF_ALLOC;
//            shdr[DYNAMIC].sh_addr = phdr[i].p_vaddr;
//            shdr[DYNAMIC].sh_offset = phdr[i].p_offset;
//            shdr[DYNAMIC].sh_size = phdr[i].p_filesz;
//            shdr[DYNAMIC].sh_link = 2;
//            shdr[DYNAMIC].sh_info = 0;
//            shdr[DYNAMIC].sh_addralign = 4;
//            shdr[DYNAMIC].sh_entsize = 8;
//            dyn_size = phdr[i].p_filesz;
//            dyn_off = phdr[i].p_offset;
//            continue;
//        }
//
//        if(phdr[i].p_type == PT_LOPROC || phdr[i].p_type == PT_LOPROC + 1) {
//            shdr[ARMEXIDX].sh_name = strstr(str, ".ARM.exidx") - str;
//            shdr[ARMEXIDX].sh_type = SHT_LOPROC;
//            shdr[ARMEXIDX].sh_flags = SHF_ALLOC;
//            shdr[ARMEXIDX].sh_addr = phdr[i].p_vaddr;
//            shdr[ARMEXIDX].sh_offset = phdr[i].p_offset;
//            shdr[ARMEXIDX].sh_size = phdr[i].p_filesz;
//            shdr[ARMEXIDX].sh_link = 7;
//            shdr[ARMEXIDX].sh_info = 0;
//            shdr[ARMEXIDX].sh_addralign = 4;
//            shdr[ARMEXIDX].sh_entsize = 8;
//            continue;
//        }
//    }
//
//    dyn = (Elf32_Dyn*)malloc(dyn_size);
//    memcpy(dyn,buffer+dyn_off,dyn_size);
//    i = 0;
//    for (; i < dyn_size / sizeof(Elf32_Dyn); i++) {
//        switch (dyn[i].d_tag) {
//            case DT_SYMTAB:
//                shdr[DYNSYM].sh_name = strstr(str, ".dynsym") - str;
//                shdr[DYNSYM].sh_type = SHT_DYNSYM;
//                shdr[DYNSYM].sh_flags = SHF_ALLOC;
//                shdr[DYNSYM].sh_addr = dyn[i].d_un.d_ptr;
//                shdr[DYNSYM].sh_offset = dyn[i].d_un.d_ptr;
//                shdr[DYNSYM].sh_link = 2;
//                shdr[DYNSYM].sh_info = 1;
//                shdr[DYNSYM].sh_addralign = 4;
//                shdr[DYNSYM].sh_entsize = 16;
//                break;
//
//            case DT_STRTAB:
//                shdr[DYNSTR].sh_name = strstr(str, ".dynstr") - str;
//                shdr[DYNSTR].sh_type = SHT_STRTAB;
//                shdr[DYNSTR].sh_flags = SHF_ALLOC;
//                shdr[DYNSTR].sh_offset = dyn[i].d_un.d_ptr;
//                shdr[DYNSTR].sh_addr = dyn[i].d_un.d_ptr;
//                shdr[DYNSTR].sh_addralign = 1;
//                shdr[DYNSTR].sh_entsize = 0;
//                break;
//
//            case DT_HASH:
//                shdr[HASH].sh_name = strstr(str, ".hash") - str;
//                shdr[HASH].sh_type = SHT_HASH;
//                shdr[HASH].sh_flags = SHF_ALLOC;
//                shdr[HASH].sh_addr = dyn[i].d_un.d_ptr;
//                shdr[HASH].sh_offset = dyn[i].d_un.d_ptr;
//                memcpy(&nbucket, buffer + shdr[HASH].sh_offset, 4);
//                memcpy(&nchain, buffer + shdr[HASH].sh_offset + 4, 4);
//                shdr[HASH].sh_size = (nbucket + nchain + 2) * sizeof(int);
//                shdr[HASH].sh_link = 4;
//                shdr[HASH].sh_info = 1;
//                shdr[HASH].sh_addralign = 4;
//                shdr[HASH].sh_entsize = 4;
//                break;
//
//            case DT_REL:
//                shdr[RELDYN].sh_name = strstr(str, ".rel.dyn") - str;
//                shdr[RELDYN].sh_type = SHT_REL;
//                shdr[RELDYN].sh_flags = SHF_ALLOC;
//                shdr[RELDYN].sh_addr = dyn[i].d_un.d_ptr;
//                shdr[RELDYN].sh_offset = dyn[i].d_un.d_ptr;
//                shdr[RELDYN].sh_link = 4;
//                shdr[RELDYN].sh_info = 0;
//                shdr[RELDYN].sh_addralign = 4;
//                shdr[RELDYN].sh_entsize = 8;
//                break;
//
//            case DT_JMPREL:
//                shdr[RELPLT].sh_name = strstr(str, ".rel.plt") - str;
//                shdr[RELPLT].sh_type = SHT_PROGBITS;
//                shdr[RELPLT].sh_flags = SHF_ALLOC;
//                shdr[RELPLT].sh_addr = dyn[i].d_un.d_ptr;
//                shdr[RELPLT].sh_offset = dyn[i].d_un.d_ptr;
//                shdr[RELPLT].sh_link = 1;
//                shdr[RELPLT].sh_info = 6;
//                shdr[RELPLT].sh_addralign = 4;
//                shdr[RELPLT].sh_entsize = 8;
//                break;
//
//            case DT_PLTRELSZ:
//                shdr[RELPLT].sh_size = dyn[i].d_un.d_val;
//                break;
//
//            case DT_FINI:
//                shdr[FINIARRAY].sh_name = strstr(str, ".fini_array") - str;
//                shdr[FINIARRAY].sh_type = 15;
//                shdr[FINIARRAY].sh_flags = SHF_WRITE | SHF_ALLOC;
//                shdr[FINIARRAY].sh_offset = dyn[i].d_un.d_ptr - 0x1000;
//                shdr[FINIARRAY].sh_addr = dyn[i].d_un.d_ptr;
//                shdr[FINIARRAY].sh_addralign = 4;
//                shdr[FINIARRAY].sh_entsize = 0;
//                break;
//
//            case DT_INIT:
//                shdr[INITARRAY].sh_name = strstr(str, ".init_array") - str;
//                shdr[INITARRAY].sh_type = 14;
//                shdr[INITARRAY].sh_flags = SHF_WRITE | SHF_ALLOC;
//                shdr[INITARRAY].sh_offset = dyn[i].d_un.d_ptr - 0x1000;
//                shdr[INITARRAY].sh_addr = dyn[i].d_un.d_ptr;
//                shdr[INITARRAY].sh_addralign = 4;
//                shdr[INITARRAY].sh_entsize = 0;
//                break;
//
//            case DT_RELSZ:
//                shdr[RELDYN].sh_size = dyn[i].d_un.d_val;
//                break;
//
//            case DT_STRSZ:
//                shdr[DYNSTR].sh_size = dyn[i].d_un.d_val;
//                break;
//
//            case DT_PLTGOT:
//                shdr[GOT].sh_name = strstr(str, ".got") - str;
//                shdr[GOT].sh_type = SHT_PROGBITS;
//                shdr[GOT].sh_flags = SHF_WRITE | SHF_ALLOC;
//                shdr[GOT].sh_addr = shdr[DYNAMIC].sh_addr + shdr[DYNAMIC].sh_size;
//                shdr[GOT].sh_offset = shdr[GOT].sh_addr - 0x1000;
//                shdr[GOT].sh_size = dyn[i].d_un.d_ptr;
//                shdr[GOT].sh_addralign = 4;
//                break;
//        }
//    }
//    shdr[GOT].sh_size = shdr[GOT].sh_size + 4 * (shdr[RELPLT].sh_size) / sizeof(Elf32_Rel) + 3 * sizeof(int) - shdr[GOT].sh_addr;
//
//    //STRTAB地址 - SYMTAB地址 = SYMTAB大小
//    shdr[DYNSYM].sh_size = shdr[DYNSTR].sh_addr - shdr[DYNSYM].sh_addr;
//
//    shdr[FINIARRAY].sh_size = shdr[INITARRAY].sh_addr - shdr[FINIARRAY].sh_addr;
//    shdr[INITARRAY].sh_size = shdr[DYNAMIC].sh_addr - shdr[INITARRAY].sh_addr;
//
//    shdr[PLT].sh_name = strstr(str, ".plt") - str;
//    shdr[PLT].sh_type = SHT_PROGBITS;
//    shdr[PLT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
//    shdr[PLT].sh_addr = shdr[RELPLT].sh_addr + shdr[RELPLT].sh_size;
//    shdr[PLT].sh_offset = shdr[PLT].sh_addr;
//    shdr[PLT].sh_size = (20 + 12 * (shdr[RELPLT].sh_size) / sizeof(Elf32_Rel));
//    shdr[PLT].sh_addralign = 4;
//
//    shdr[TEXT].sh_name = strstr(str, ".text") - str;
//    shdr[TEXT].sh_type = SHT_PROGBITS;
//    shdr[TEXT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
//    shdr[TEXT].sh_addr = shdr[PLT].sh_addr + shdr[PLT].sh_size;
//    shdr[TEXT].sh_offset = shdr[TEXT].sh_addr;
//    shdr[TEXT].sh_size = shdr[ARMEXIDX].sh_addr - shdr[TEXT].sh_addr;
//
//    shdr[DATA].sh_name = strstr(str, ".data") - str;
//    shdr[DATA].sh_type = SHT_PROGBITS;
//    shdr[DATA].sh_flags = SHF_WRITE | SHF_ALLOC;
//    shdr[DATA].sh_addr = shdr[GOT].sh_addr + shdr[GOT].sh_size;
//    shdr[DATA].sh_offset = shdr[DATA].sh_addr - 0x1000;
//    shdr[DATA].sh_size = load.p_vaddr + load.p_filesz - shdr[DATA].sh_addr;
//    shdr[DATA].sh_addralign = 4;
//
//    shdr[STRTAB].sh_name = strstr(str, ".shstrtab") - str;
//    shdr[STRTAB].sh_type = SHT_STRTAB;
//    shdr[STRTAB].sh_flags = SHT_NULL;
//    shdr[STRTAB].sh_addr = 0;
//    shdr[STRTAB].sh_offset = shdr[BSS].sh_addr - 0x1000;
//    shdr[STRTAB].sh_size = strlen(str) + 1;
//    shdr[STRTAB].sh_addralign = 1;
//    //memcpy(buffer + shdr[STRTAB].sh_offset, str, strlen(str));
//    memcpy(*sh_buffer,shdr,sizeof(shdr));
    return true;
}

bool ElfRebuilder::Rebuild() {
    return RebuildPhdr() && ReadSoInfo() && RebuildShdr() && RebuildElf();
}

bool ElfRebuilder::ReadSoInfo() {
    si.base = si.load_bias = elf_reader_->load_bias();
    si.phdr = elf_reader_->loaded_phdr();
    si.phnum = elf_reader_->phdr_count();
    auto base = si.load_bias;
    phdr_table_get_load_size(si.phdr, si.phnum, &si.min_load, &si.max_load);

    /* Extract dynamic section */
    phdr_table_get_dynamic_section(si.phdr, si.phnum, si.base, &si.dynamic,
                                   &si.dynamic_count, &si.dynamic_flags);
    if(si.dynamic == nullptr) {
        DL_ERR("No valid dynamic phdr data\n");
        return false;
    }

    phdr_table_get_arm_exidx(si.phdr, si.phnum, si.base,
                             &si.ARM_exidx, &si.ARM_exidx_count);

    // Extract useful information from dynamic section.
    uint32_t needed_count = 0;
    for (Elf_Dyn* d = si.dynamic; d->d_tag != DT_NULL; ++d) {
        DL_ERR("d = %p, d[0](tag) = 0x%08x d[1](val) = 0x%08x\n", d, d->d_tag, d->d_un.d_val);
        switch(d->d_tag){
            case DT_HASH:
                si.hash = d->d_un.d_ptr + base;
                si.nbucket = ((unsigned *) (base + d->d_un.d_ptr))[0];
                si.nchain = ((unsigned *) (base + d->d_un.d_ptr))[1];
                si.bucket = (unsigned *) (base + d->d_un.d_ptr + 8);
                si.chain = (unsigned *) (base + d->d_un.d_ptr + 8 + si.nbucket * 4);
                break;
            case DT_STRTAB:
                si.strtab = (const char *) (base + d->d_un.d_ptr);
                break;
            case DT_SYMTAB:
                si.symtab = (Elf_Sym *) (base + d->d_un.d_ptr);
                break;
            case DT_PLTREL:
                if (d->d_un.d_val != DT_REL) {
                    DL_ERR("unsupported DT_RELA in \"%s\"\n", si.name);
                    return false;
                }
                break;
            case DT_JMPREL:
                si.plt_rel = (Elf_Rel*) (base + d->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                si.plt_rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                break;
            case DT_REL:
                si.rel = (Elf_Rel*) (base + d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                si.rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                break;
            case DT_PLTGOT:
                /* Save this in case we decide to do lazy binding. We don't yet. */
                si.plt_got = (Elf_Addr *)(base + d->d_un.d_ptr);
                break;
            case DT_DEBUG:
                // Set the DT_DEBUG entry to the address of _r_debug for GDB
                // if the dynamic table is writable
                break;
            case DT_RELA:
                DL_ERR("unsupported DT_RELA in \"%s\"\n", si.name);
                return false;
            case DT_INIT:
                si.init_func = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                DL_ERR("%s constructors (DT_INIT) found at %p\n", si.name, si.init_func);
                break;
            case DT_FINI:
                si.fini_func = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                DL_ERR("%s destructors (DT_FINI) found at %p\n", si.name, si.fini_func);
                break;
            case DT_INIT_ARRAY:
                si.init_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                DL_ERR("%s constructors (DT_INIT_ARRAY) found at %p\n", si.name, si.init_array);
                break;
            case DT_INIT_ARRAYSZ:
                si.init_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                break;
            case DT_FINI_ARRAY:
                si.fini_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                DL_ERR("%s destructors (DT_FINI_ARRAY) found at %p\n", si.name, si.fini_array);
                break;
            case DT_FINI_ARRAYSZ:
                si.fini_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                break;
            case DT_PREINIT_ARRAY:
                si.preinit_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                DL_ERR("%s constructors (DT_PREINIT_ARRAY) found at %p\n", si.name, si.preinit_array);
                break;
            case DT_PREINIT_ARRAYSZ:
                si.preinit_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                break;
            case DT_TEXTREL:
                si.has_text_relocations = true;
                break;
            case DT_SYMBOLIC:
                si.has_DT_SYMBOLIC = true;
                break;
            case DT_NEEDED:
                ++needed_count;
                break;
            case DT_FLAGS:
                if (d->d_un.d_val & DF_TEXTREL) {
                    si.has_text_relocations = true;
                }
                if (d->d_un.d_val & DF_SYMBOLIC) {
                    si.has_DT_SYMBOLIC = true;
                }
                break;
            case DT_STRSZ:
                si.strtabsize = d->d_un.d_val;
                break;
            case DT_SYMENT:
            case DT_RELENT:
                break;
            case DT_MIPS_RLD_MAP:
                // Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB.
                break;
            case DT_MIPS_RLD_VERSION:
            case DT_MIPS_FLAGS:
            case DT_MIPS_BASE_ADDRESS:
            case DT_MIPS_UNREFEXTNO:
                break;

            case DT_MIPS_SYMTABNO:
                si.mips_symtabno = d->d_un.d_val;
                break;

            case DT_MIPS_LOCAL_GOTNO:
                si.mips_local_gotno = d->d_un.d_val;
                break;

            case DT_MIPS_GOTSYM:
                si.mips_gotsym = d->d_un.d_val;
                break;

            default:
                DL_ERR("Unused DT entry: type 0x%08x arg 0x%08x\n", d->d_tag, d->d_un.d_val);
                break;
        }
    }
    return true;
}

bool ElfRebuilder::RebuildElf() {
    auto load_size = si.max_load - si.min_load;
    rebuild_size = load_size + shstrtab.length() +
            shdrs.size() * sizeof(Elf_Shdr);
    rebuild_data = new uint8_t[rebuild_size];
    memcpy(rebuild_data, (void*)si.load_bias, load_size);
    // pad with shstrtab
    memcpy(rebuild_data + load_size, shstrtab.c_str(), shstrtab.length());
    // pad with shdrs
    auto shdr_off = load_size + shstrtab.length();
    memcpy(rebuild_data + (int)shdr_off, (void*)&shdrs[0],
           shdrs.size() * sizeof(Elf_Shdr));
    auto ehdr = *elf_reader_->record_ehdr();
    ehdr.e_shnum = shdrs.size();
    ehdr.e_shoff = (Elf_Addr)shdr_off;
    ehdr.e_shstrndx = sSHSTRTAB;
    memcpy(rebuild_data, &ehdr, sizeof(Elf_Ehdr));

    return true;
}




