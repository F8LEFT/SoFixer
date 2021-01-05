//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2021/1/5.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
#ifndef SOFIXER_FILEREADER_H
#define SOFIXER_FILEREADER_H

#include "macros.h"
#include "FDebug.h"
#include <cerrno>
#include <cstdio>
#include <cstring>

class FileReader {
public:
    FileReader(const char* name): source(name){}
    ~FileReader() {
        Close();
    }
    bool Open() {
        if (IsValid()) {
            return false;
        }
        fp = fopen(source, "rb");
        if (fp == nullptr) {
            return false;
        }
        fseek(fp, 0, SEEK_END);
        file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        return true;
    }
    bool Close() {
        if (IsValid()) {
            auto err = fclose(fp);
            fp = nullptr;
            return err == 0;
        }
        return false;
    }
    bool IsValid() {
        return fp != nullptr;
    }
    const char* getSource() {
        return source;
    }
    size_t Read(void *addr, size_t len, int offset = -1) {
        if (offset >= 0) {
            fseek(fp, offset, SEEK_SET);
        }
        auto rc = TEMP_FAILURE_RETRY(fread(addr, 1, len, fp));

        if (rc < 0) {
            FLOGE("can't read file \"%s\": %s", source, strerror(errno));
            return rc;
        }
        if (rc != len) {
            FLOGE("\"%s\" has no enough data at %x:%zx, not a valid file or you need to dump more data", source, offset, len);
            return rc;
        }
        return rc;
    }
    long FileSize() {
        return file_size;
    }
private:
    FILE* fp = nullptr;
    const char* source = nullptr;
    long file_size;
};

#endif //SOFIXER_FILEREADER_H
