//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/3.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//

#include "ElfReader.h"
#include "elf.h"
#include "FDebug.h"
#include <stdio.h>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <vector>

/**
  TECHNICAL NOTE ON ELF LOADING.

  An ELF file's program header table contains one or more PT_LOAD
  segments, which corresponds to portions of the file that need to
  be mapped into the process' address space.

  Each loadable segment has the following important properties:

    p_offset  -> segment file offset
    p_filesz  -> segment file size
    p_memsz   -> segment memory size (always >= p_filesz)
    p_vaddr   -> segment's virtual address
    p_flags   -> segment flags (e.g. readable, writable, executable)

  We will ignore the p_paddr and p_align fields of Elf32_Phdr for now.

  The loadable segments can be seen as a list of [p_vaddr ... p_vaddr+p_memsz)
  ranges of virtual addresses. A few rules apply:

  - the virtual address ranges should not overlap.

  - if a segment's p_filesz is smaller than its p_memsz, the extra bytes
    between them should always be initialized to 0.

  - ranges do not necessarily start or end at page boundaries. Two distinct
    segments can have their start and end on the same page. In this case, the
    page inherits the mapping flags of the latter segment.

  Finally, the real load addrs of each segment is not p_vaddr. Instead the
  loader decides where to load the first segment, then will load all others
  relative to the first one to respect the initial range layout.

  For example, consider the following list:

    [ offset:0,      filesz:0x4000, memsz:0x4000, vaddr:0x30000 ],
    [ offset:0x4000, filesz:0x2000, memsz:0x8000, vaddr:0x40000 ],

  This corresponds to two segments that cover these virtual address ranges:

       0x30000...0x34000
       0x40000...0x48000

  If the loader decides to load the first segment at address 0xa0000000
  then the segments' load address ranges will be:

       0xa0030000...0xa0034000
       0xa0040000...0xa0048000

  In other words, all segments must be loaded at an address that has the same
  constant offset from their p_vaddr value. This offset is computed as the
  difference between the first segment's load address, and its p_vaddr value.

  However, in practice, segments do _not_ start at page boundaries. Since we
  can only memory-map at page boundaries, this means that the bias is
  computed as:

       load_bias = phdr0_load_address - PAGE_START(phdr0->p_vaddr)

  (NOTE: The value must be used as a 32-bit unsigned integer, to deal with
          possible wrap around UINT32_MAX for possible large p_vaddr values).

  And that the phdr0_load_address must start at a page boundary, with
  the segment's real content starting at:

       phdr0_load_address + PAGE_OFFSET(phdr0->p_vaddr)

  Note that ELF requires the following condition to make the mmap()-ing work:

      PAGE_OFFSET(phdr0->p_vaddr) == PAGE_OFFSET(phdr0->p_offset)

  The load_bias must be added to any p_vaddr value read from the ELF file to
  determine the corresponding memory address.

 **/


#define MAYBE_MAP_FLAG(x,from,to)    (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
ElfReader::ElfReader()
        : source_(nullptr), name_(nullptr), fd_(-1),
          phdr_num_(0), phdr_mmap_(NULL), phdr_table_(NULL), phdr_size_(0),
          load_start_(NULL), load_size_(0), load_bias_(0),
          loaded_phdr_(NULL) {
}

ElfReader::~ElfReader() {
    if (phdr_mmap_ != NULL) {
        delete [](uint8_t*)phdr_mmap_;
    }
    if(load_start_ != nullptr) {
        delete [](uint8_t*)load_start_;
    }
}

bool ElfReader::Load() {
    // try open
    return ReadElfHeader() &&
           VerifyElfHeader() &&
           ReadProgramHeader() &&
           ReserveAddressSpace() &&
           LoadSegments() &&
           FindPhdr() &&
           PatchPhdr();
}

bool ElfReader::ReadElfHeader() {
    ssize_t rc = read(fd_, &header_, sizeof(header_));
    if (rc < 0) {
        FLOGE("can't read file \"%s\": %s", name_, strerror(errno));
        return false;
    }
    if (rc != sizeof(header_)) {
        FLOGE("\"%s\" is too small to be an ELF executable", name_);
        return false;
    }
    return true;
}

bool ElfReader::VerifyElfHeader() {
    if (header_.e_ident[EI_MAG0] != ELFMAG0 ||
        header_.e_ident[EI_MAG1] != ELFMAG1 ||
        header_.e_ident[EI_MAG2] != ELFMAG2 ||
        header_.e_ident[EI_MAG3] != ELFMAG3) {
        FLOGE("\"%s\" has bad ELF magic", name_);
        return false;
    }
#ifndef __SO64__
    if (header_.e_ident[EI_CLASS] != ELFCLASS32) {
        FLOGE("\"%s\" not 32-bit: %d", name_, header_.e_ident[EI_CLASS]);
        return false;
    }
#else
    if (header_.e_ident[EI_CLASS] != ELFCLASS64) {
        FLOGE("\"%s\" not 64-bit: %d", name_, header_.e_ident[EI_CLASS]);
        return false;
    }
#endif

    if (header_.e_ident[EI_DATA] != ELFDATA2LSB) {
        FLOGE("\"%s\" not little-endian: %d", name_, header_.e_ident[EI_DATA]);
        return false;
    }

    if (header_.e_type != ET_DYN) {
        FLOGE("\"%s\" has unexpected e_type: %d", name_, header_.e_type);
        return false;
    }

    if (header_.e_version != EV_CURRENT) {
        FLOGE("\"%s\" has unexpected e_version: %d", name_, header_.e_version);
        return false;
    }

    return true;
}

// Loads the program header table from an ELF file into a read-only private
// anonymous mmap-ed block.
bool ElfReader::ReadProgramHeader() {
    phdr_num_ = header_.e_phnum;

    // Like the kernel, we only accept program header tables that
    // are smaller than 64KiB.
    if (phdr_num_ < 1 || phdr_num_ > 65536/sizeof(Elf_Phdr)) {
        FLOGE("\"%s\" has invalid e_phnum: %zu", name_, phdr_num_);
        return false;
    }

    phdr_size_ = phdr_num_ * sizeof(Elf_Phdr);
    void* mmap_result = new uint8_t[phdr_size_];
    if(!LoadFileData(mmap_result, phdr_size_, header_.e_phoff)) {
        FLOGE("\"%s\" has no valid phdr data", name_);
        return false;
    }

    phdr_mmap_ = mmap_result;
    phdr_table_ = reinterpret_cast<Elf_Phdr*>(reinterpret_cast<char*>(mmap_result));

    if(dump_so_file_) {
        auto phdr = phdr_table_;
        for(auto i = 0; i < phdr_num_; i++) {
            phdr->p_filesz = phdr->p_memsz;     // expend filesize to memsiz
            phdr->p_paddr = phdr->p_vaddr;
            phdr->p_offset = phdr->p_vaddr;     // elf has been loaded.
            phdr++;
        }
        // fix phdr, just load all data
        std::vector<Elf32_Phdr*> loaded_phdrs;
        for (auto i = 0; i < phdr_num_; i++) {
            auto phdr = &phdr_table_[i];
            if(phdr->p_type != PT_LOAD) continue;
            loaded_phdrs.push_back(phdr);
        }
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
    return true;
}

/* Returns the size of the extent of all the possibly non-contiguous
 * loadable segments in an ELF program header table. This corresponds
 * to the page-aligned size in bytes that needs to be reserved in the
 * process' address space. If there are no loadable segments, 0 is
 * returned.
 *
 * If out_min_vaddr or out_max_vaddr are non-NULL, they will be
 * set to the minimum and maximum addresses of pages to be reserved,
 * or 0 if there is nothing to load.
 */
size_t phdr_table_get_load_size(const Elf_Phdr* phdr_table,
                                size_t phdr_count,
                                Elf_Addr* out_min_vaddr,
                                Elf_Addr* out_max_vaddr)
{
    Elf_Addr min_vaddr = 0xFFFFFFFFU;
    Elf_Addr max_vaddr = 0x00000000U;

    bool found_pt_load = false;
    for (size_t i = 0; i < phdr_count; ++i) {
        const Elf_Phdr* phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        found_pt_load = true;

        if (phdr->p_vaddr < min_vaddr) {
            min_vaddr = phdr->p_vaddr;
        }

        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
            max_vaddr = phdr->p_vaddr + phdr->p_memsz;
        }
    }
    if (!found_pt_load) {
        min_vaddr = 0x00000000U;
    }

    min_vaddr = PAGE_START(min_vaddr);
    max_vaddr = PAGE_END(max_vaddr);

    if (out_min_vaddr != NULL) {
        *out_min_vaddr = min_vaddr;
    }
    if (out_max_vaddr != NULL) {
        *out_max_vaddr = max_vaddr;
    }
    return max_vaddr - min_vaddr;
}

// Reserve a virtual address range big enough to hold all loadable
// segments of a program header table. This is done by creating a
// private anonymous mmap() with PROT_NONE.
bool ElfReader::ReserveAddressSpace() {
    Elf_Addr min_vaddr;
    load_size_ = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr);
    if (load_size_ == 0) {
        FLOGE("\"%s\" has no loadable segments", name_);
        return false;
    }

    uint8_t* addr = reinterpret_cast<uint8_t*>(min_vaddr);
    // alloc map data, and load in addr
    uint8_t * start = new uint8_t[load_size_];

    load_start_ = start;
    load_bias_ = reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t >(start)
       - reinterpret_cast<uintptr_t >(addr));
    return true;
}

// Map all loadable segments in process' address space.
// This assumes you already called phdr_table_reserve_memory to
// reserve the address space range for the library.
// TODO: assert assumption.
bool ElfReader::LoadSegments() {
    // TODO fix file dada load error, file data between LOAD seg should be loaded
    for (size_t i = 0; i < phdr_num_; ++i) {
        const Elf_Phdr* phdr = &phdr_table_[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        // Segment addresses in memory.
        Elf_Addr seg_start = phdr->p_vaddr;
        Elf_Addr seg_end   = seg_start + phdr->p_memsz;

        Elf_Addr seg_page_start = PAGE_START(seg_start);
        Elf_Addr seg_page_end   = PAGE_END(seg_end);

        Elf_Addr seg_file_end   = seg_start + phdr->p_filesz;

        // File offsets.
        Elf_Addr file_start = phdr->p_offset;
        Elf_Addr file_end   = file_start + phdr->p_filesz;

        Elf_Addr file_page_start = PAGE_START(file_start);
        Elf_Addr file_length = file_end - file_page_start;


        if (file_length != 0) {
            // memory data loading
            void* load_point = seg_page_start + reinterpret_cast<uint8_t *>(load_bias_);
            if(!LoadFileData(load_point, file_length, file_page_start)) {
                FLOGE("couldn't map \"%s\" segment %zu: %s", name_, i, strerror(errno));
                return false;
            }

        }

        // if the segment is writable, and does not end on a page boundary,
        // zero-fill it until the page limit.
        if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(seg_file_end) > 0) {
            memset(seg_file_end + reinterpret_cast<uint8_t *>(load_bias_), 0, PAGE_SIZE - PAGE_OFFSET(seg_file_end));
        }

        seg_file_end = PAGE_END(seg_file_end);

        // seg_file_end is now the first page address after the file
        // content. If seg_end is larger, we need to zero anything
        // between them. This is done by using a private anonymous
        // map for all extra pages.
        if (seg_page_end > seg_file_end) {
            void* load_point = (uint8_t*)load_bias_ + seg_file_end;
            memset(load_point, 0, seg_page_end - seg_file_end);
        }
    }
    return true;
}

/* Used internally. Used to set the protection bits of all loaded segments
 * with optional extra flags (i.e. really PROT_WRITE). Used by
 * phdr_table_protect_segments and phdr_table_unprotect_segments.
 */
static int
_phdr_table_set_load_prot(const Elf_Phdr* phdr_table,
                          int               phdr_count,
                          uint8_t *load_bias,
                          int               extra_prot_flags)
{
    const Elf_Phdr* phdr = phdr_table;
    const Elf_Phdr* phdr_limit = phdr + phdr_count;

    for (; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_W) != 0)
            continue;

        auto seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
        auto seg_page_end   = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

        auto ret = 0;

//        int ret = mprotect((void*)seg_page_start,
//                           seg_page_end - seg_page_start,
//                           PFLAGS_TO_PROT(phdr->p_flags) | extra_prot_flags);
//        if (ret < 0) {
//            return -1;
//        }
    }
    return 0;
}

/* Restore the original protection modes for all loadable segments.
 * You should only call this after phdr_table_unprotect_segments and
 * applying all relocations.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Return:
 *   0 on error, -1 on failure (error code in errno).
 */
int
phdr_table_protect_segments(const Elf_Phdr* phdr_table,
                            int               phdr_count,
                            uint8_t *load_bias)
{
    return _phdr_table_set_load_prot(phdr_table, phdr_count,
                                     load_bias, 0);
}

/* Change the protection of all loaded segments in memory to writable.
 * This is useful before performing relocations. Once completed, you
 * will have to call phdr_table_protect_segments to restore the original
 * protection flags on all segments.
 *
 * Note that some writable segments can also have their content turned
 * to read-only by calling phdr_table_protect_gnu_relro. This is no
 * performed here.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Return:
 *   0 on error, -1 on failure (error code in errno).
 */
int
phdr_table_unprotect_segments(const Elf_Phdr* phdr_table,
                              int               phdr_count,
                              uint8_t *load_bias)
{
    return _phdr_table_set_load_prot(phdr_table, phdr_count,
                                     load_bias, /*PROT_WRITE*/0);
}

/* Used internally by phdr_table_protect_gnu_relro and
 * phdr_table_unprotect_gnu_relro.
 */
static int
_phdr_table_set_gnu_relro_prot(const Elf_Phdr* phdr_table,
                               int               phdr_count,
                               uint8_t *load_bias,
                               int               prot_flags)
{
    const Elf_Phdr* phdr = phdr_table;
    const Elf_Phdr* phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
//        if (phdr->p_type != PT_GNU_RELRO)
//            continue;

        /* Tricky: what happens when the relro segment does not start
         * or end at page boundaries?. We're going to be over-protective
         * here and put every page touched by the segment as read-only.
         *
         * This seems to match Ian Lance Taylor's description of the
         * feature at http://www.airs.com/blog/archives/189.
         *
         * Extract:
         *    Note that the current dynamic linker code will only work
         *    correctly if the PT_GNU_RELRO segment starts on a page
         *    boundary. This is because the dynamic linker rounds the
         *    p_vaddr field down to the previous page boundary. If
         *    there is anything on the page which should not be read-only,
         *    the program is likely to fail at runtime. So in effect the
         *    linker must only emit a PT_GNU_RELRO segment if it ensures
         *    that it starts on a page boundary.
         */
        auto seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
        auto seg_page_end   = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

        auto ret = 0;
//        int ret = mprotect((void*)seg_page_start,
//                           seg_page_end - seg_page_start,
//                           prot_flags);
//        if (ret < 0) {
//            return -1;
//        }
    }
    return 0;
}

/* Apply GNU relro protection if specified by the program header. This will
 * turn some of the pages of a writable PT_LOAD segment to read-only, as
 * specified by one or more PT_GNU_RELRO segments. This must be always
 * performed after relocations.
 *
 * The areas typically covered are .got and .data.rel.ro, these are
 * read-only from the program's POV, but contain absolute addresses
 * that need to be relocated before use.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Return:
 *   0 on error, -1 on failure (error code in errno).
 */
int
phdr_table_protect_gnu_relro(const Elf_Phdr* phdr_table,
                             int               phdr_count,
                             uint8_t *load_bias)
{
    return _phdr_table_set_gnu_relro_prot(phdr_table,
                                          phdr_count,
                                          load_bias,
                                          /*PROT_READ*/0);
}


#  ifndef PT_ARM_EXIDX
#    define PT_ARM_EXIDX    0x70000001      /* .ARM.exidx segment */
#  endif

/* Return the address and size of the .ARM.exidx section in memory,
 * if present.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   arm_exidx       -> address of table in memory (NULL on failure).
 *   arm_exidx_count -> number of items in table (0 on failure).
 * Return:
 *   0 on error, -1 on failure (_no_ error code in errno)
 */
int
phdr_table_get_arm_exidx(const Elf_Phdr* phdr_table,
                         int               phdr_count,
                         uint8_t * load_bias,
                         Elf_Addr**      arm_exidx,
                         unsigned*         arm_exidx_count)
{
    const Elf_Phdr* phdr = phdr_table;
    const Elf_Phdr* phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_ARM_EXIDX)
            continue;

        *arm_exidx = (Elf_Addr*)((uint8_t *)load_bias + phdr->p_vaddr);
        *arm_exidx_count = (unsigned)(phdr->p_memsz / sizeof(Elf_Addr));
        return 0;
    }
    *arm_exidx = NULL;
    *arm_exidx_count = 0;
    return -1;
}

/* Return the address and size of the ELF file's .dynamic section in memory,
 * or NULL if missing.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   dynamic       -> address of table in memory (NULL on failure).
 *   dynamic_count -> number of items in table (0 on failure).
 *   dynamic_flags -> protection flags for section (unset on failure)
 * Return:
 *   void
 */
void
phdr_table_get_dynamic_section(const Elf_Phdr* phdr_table,
                               int               phdr_count,
                               uint8_t *load_bias,
                               Elf_Dyn**       dynamic,
                               size_t*           dynamic_count,
                               Elf_Word*       dynamic_flags)
{
    const Elf_Phdr* phdr = phdr_table;
    const Elf_Phdr* phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }

        *dynamic = reinterpret_cast<Elf_Dyn*>(load_bias + phdr->p_vaddr);
        if (dynamic_count) {
            *dynamic_count = (unsigned)(phdr->p_memsz / sizeof(Elf_Dyn));
        }
        if (dynamic_flags) {
            *dynamic_flags = phdr->p_flags;
        }
        return;
    }
    *dynamic = NULL;
    if (dynamic_count) {
        *dynamic_count = 0;
    }
}

// Returns the address of the program header table as it appears in the loaded
// segments in memory. This is in contrast with 'phdr_table_' which
// is temporary and will be released before the library is relocated.
bool ElfReader::FindPhdr() {
    const Elf_Phdr* phdr_limit = phdr_table_ + phdr_num_;

    // If there is a PT_PHDR, use it directly.
    for (const Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            return CheckPhdr((uint8_t*)load_bias_ + phdr->p_vaddr);
        }
    }

    // Otherwise, check the first loadable segment. If its file offset
    // is 0, it starts with the ELF header, and we can trivially find the
    // loaded program header from it.
    for (const Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_offset == 0) {
                uint8_t *elf_addr = (uint8_t*)load_bias_ + phdr->p_vaddr;
                const Elf_Ehdr* ehdr = (const Elf_Ehdr*)(void*)elf_addr;
                Elf_Addr  offset = ehdr->e_phoff;
                return CheckPhdr((uint8_t*)ehdr + offset);
            }
            break;
        }
    }

    FLOGE("can't find loaded phdr for \"%s\"", name_);
    return false;
}

bool ElfReader::PatchPhdr() {
    const Elf_Phdr* phdr_limit = phdr_table_ + phdr_num_;
    memcpy((void*)loaded_phdr_, (void*)phdr_table_, (uintptr_t)phdr_limit - (uintptr_t)phdr_table_ );
    return true;
}

// Ensures that our program header is actually within a loadable
// segment. This should help catch badly-formed ELF files that
// would cause the linker to crash later when trying to access it.
bool ElfReader::CheckPhdr(uint8_t * loaded) {
    const Elf_Phdr* phdr_limit = phdr_table_ + phdr_num_;
    auto loaded_end = loaded + (phdr_num_ * sizeof(Elf_Phdr));
    for (Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        auto seg_start = phdr->p_vaddr + (uint8_t*)load_bias_;
        auto seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            loaded_phdr_ = reinterpret_cast<const Elf_Phdr*>(loaded);
            return true;
        }
    }
    FLOGE("\"%s\" loaded phdr %p not in loadable segment", name_, loaded);
    return false;
}

bool ElfReader::LoadFileData(void *addr, size_t len, int offset) {
    lseek(fd_, offset, SEEK_SET);
    auto rc = read(fd_, addr, len);

    if (rc < 0) {
        FLOGE("can't read file \"%s\": %s", name_, strerror(errno));
        return false;
    }
    if (rc != len) {
        FLOGE("\"%s\" has no enough data at %x:%zx, not a valid file or you need to dump more data", name_, offset, len);
        return false;
    }
    return true;
}

void ElfReader::setSource(const char *source, int fd) {
    name_ = source;
    fd_ = fd;
    file_size = lseek(fd_, 0L, SEEK_END);
    lseek(fd_, 0L, SEEK_SET);
}
