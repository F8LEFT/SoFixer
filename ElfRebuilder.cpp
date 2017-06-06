//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/4.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
#include <cstdio>
#include "ElfRebuilder.h"

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
//        shdr.sh_info = 1;
        shdr.sh_info = 0;
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
        // Align 8
        while (shdr.sh_addr & 0x7) {
            shdr.sh_addr ++;
        }

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
        // Align8??
        while (shdr.sh_addr & 0x7) {
            shdr.sh_addr ++;
        }

        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = (Elf_Addr)(si.plt_got + si.plt_rel_count) - shdr.sh_addr - base + 3 * sizeof(Elf_Addr);
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
//    if(true) {
//        sBSS = shdrs.size();
//
//        Elf_Shdr shdr;
//        shdr.sh_name = shstrtab.length();
//        shstrtab.append(".bss");
//        shstrtab.push_back('\0');
//
//        shdr.sh_type = SHT_NOBITS;
//        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
//        shdr.sh_addr = si.max_load;
//        shdr.sh_offset = shdr.sh_addr;
//        shdr.sh_size = 0;   // not used
//        shdr.sh_link = 0;
//        shdr.sh_info = 0;
//        shdr.sh_addralign = 8;
//        shdr.sh_entsize = 0x0;
//
//        shdrs.push_back(shdr);
//    }

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
    }

    // sort shdr and recalc size
    for(auto i = 1; i < shdrs.size(); i++) {
        for(auto j = i + 1; j < shdrs.size(); j++) {
            if(shdrs[i].sh_addr > shdrs[j].sh_addr) {
                // exchange i, j
                auto tmp = shdrs[i];
                shdrs[i] = shdrs[j];
                shdrs[j] = tmp;

                // exchange index
                auto chgIdx = [i, j](Elf_Word &t) {
                    if(t == i) {
                        t = j;
                    } else if(t == j) {
                        t = i;
                    }
                };
                chgIdx(sDYNSYM);
                chgIdx(sDYNSTR);
                chgIdx(sHASH);
                chgIdx(sRELDYN);
                chgIdx(sRELPLT);
                chgIdx(sPLT);
                chgIdx(sTEXTTAB);
                chgIdx(sARMEXIDX);
                chgIdx(sFINIARRAY);
                chgIdx(sINITARRAY);
                chgIdx(sDYNAMIC);
                chgIdx(sGOT);
                chgIdx(sDATA);
                chgIdx(sBSS);
                chgIdx(sSHSTRTAB);
            }
        }
    }

    if(sDYNSYM != 0) {
        auto sNext = sDYNSYM + 1;
        shdrs[sDYNSYM].sh_size = shdrs[sNext].sh_addr - shdrs[sDYNSYM].sh_addr;
    }

    if(sTEXTTAB != 0) {
        auto sNext = sTEXTTAB + 1;
        shdrs[sTEXTTAB].sh_size = shdrs[sNext].sh_addr - shdrs[sTEXTTAB].sh_addr;
    }

    // fix for size
    for(auto i = 2; i < shdrs.size(); i++) {
        if(shdrs[i].sh_offset - shdrs[i-1].sh_offset < shdrs[i-1].sh_size) {
            shdrs[i-1].sh_size = shdrs[i].sh_offset - shdrs[i-1].sh_offset;
        }
    }

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
                             &si.ARM_exidx, (unsigned*)&si.ARM_exidx_count);

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




