//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2021/1/5.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
#include "ObElfReader.h"

#include <vector>
#include <algorithm>

void ObElfReader::FixDumpSoPhdr() {
    if (dump_so_base_ != 0)
        return;

    auto phdr = phdr_table_;
    for(auto i = 0; i < phdr_num_; i++) {
        phdr->p_paddr = phdr->p_vaddr;
        phdr->p_filesz = phdr->p_memsz;     // expend filesize to memsiz
        phdr->p_offset = phdr->p_vaddr;     // since elf has been loaded. just expand file data to dump memory data
//            phdr->p_flags = 0                 // TODO fix flags by PT_TYPE
        phdr++;
    }
    // some shell will release data between loadable phdr(s), just load all memory data
    std::vector<Elf_Phdr*> loaded_phdrs;
    for (auto i = 0; i < phdr_num_; i++) {
        auto phdr = &phdr_table_[i];
        if(phdr->p_type != PT_LOAD) continue;
        loaded_phdrs.push_back(phdr);
    }
    std::sort(loaded_phdrs.begin(), loaded_phdrs.end(),
              [](Elf_Phdr * first, Elf_Phdr * second) {
                  return first->p_vaddr < second->p_vaddr;
              });
    if (!loaded_phdrs.empty()) {
        for (unsigned long i = 0, total = loaded_phdrs.size(); i < total; i++) {
            auto phdr = loaded_phdrs[i];
            if (i != total - 1) {
                // to next loaded segament
                auto nphdr = loaded_phdrs[i+1];
                phdr->p_memsz = nphdr->p_vaddr - phdr->p_vaddr;
            } else {
                // to the file end
                phdr->p_memsz = file_size - phdr->p_vaddr;
            }
            phdr->p_filesz = phdr->p_memsz;
        }
    }
}

bool ObElfReader::Load() {
    // try open
    if (!ReadElfHeader() || !VerifyElfHeader() || !ReadProgramHeader())
        return false;
    FixDumpSoPhdr();
    if (!ReserveAddressSpace() ||
        !LoadSegments() ||
        !FindPhdr()) {
        return false;
    }
    ApplyPhdrTable();

    LoadDynamicSection();
    return true;
}

void ObElfReader::GetDynamicSection(Elf_Dyn **dynamic, size_t *dynamic_count, Elf_Word *dynamic_flags) {
    if (dynamic_sections_ == nullptr) {
        ElfReader::GetDynamicSection(dynamic, dynamic_count, dynamic_flags);
        return;
    }
    *dynamic = reinterpret_cast<Elf_Dyn*>(dynamic_sections_);
    if (dynamic_count) {
        *dynamic_count = dynamic_count_;
    }
    if (dynamic_flags) {
        *dynamic_flags = dynamic_flags_;
    }
    return;
}

ObElfReader::~ObElfReader() {
    if (dynamic_sections_ != nullptr) {
        delete [](uint8_t*)dynamic_sections_;
    }
}

bool ObElfReader::LoadDynamicSection() {
    if (baseso_ == nullptr) {
        return false;
    }
    ElfReader base_reader;

    // if base so is provided, load dynamic section from base so
    if (!base_reader.setSource(baseso_) ||
        !base_reader.ReadElfHeader() ||
        !base_reader.VerifyElfHeader() ||
        !base_reader.ReadProgramHeader()) {
        FLOGE("Unable to parse base so file, is it correct?");
        return false;
    }
    const Elf_Phdr * phdr_table_ = base_reader.phdr_table_;
    const Elf_Phdr * phdr_limit = phdr_table_ + base_reader.phdr_num_;
    const Elf_Phdr * phdr;

    for (phdr = phdr_table_; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }

        dynamic_sections_ = new uint8_t [phdr->p_memsz];
        base_reader.source_->Read(dynamic_sections_, phdr->p_memsz, phdr->p_offset);

        dynamic_count_ = (unsigned)(phdr->p_memsz / sizeof(Elf_Dyn));
        dynamic_flags_ = phdr->p_flags;
        return true;
    }

    return false;
}

