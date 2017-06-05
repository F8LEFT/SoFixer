#include <iostream>
#include <io.h>
#include <fcntl.h>
#include "ElfReader.h"
#include "ElfRebuilder.h"
#include <getopt.h>
#include <string>

const char* short_options = "hds:o:";
const struct option long_options[] = {
        {"help", 0, NULL, 'h'},
        {"dumpso", 0, NULL, 'd'},
        {"source", 1, NULL, 's'},
        {"output", 1, NULL, 'o'},
        {nullptr, 0, nullptr, 0}
};
void useage();

int main(int argc, char* argv[]) {
    int c;
    std::string source, output;
    bool isDumpSoFile = false, isValidArg = true;
    while((c = getopt_long(argc, argv, short_options, long_options, nullptr)) != -1) {
        switch (c) {
            case 'd':
                isDumpSoFile = true;
                break;
            case 's':
                source = optarg;
                break;
            case 'o':
                output = optarg;
                break;
            default:
                isValidArg = false;
                break;
        }
    }
    if(!isValidArg) {
        useage();
    }

    auto fd = open(source.c_str(), O_RDONLY | O_BINARY);
    if(fd == -1) {
        printf("source so file cannot found!!!\n");
        return -1;
    }

    printf("start to rebuild elf file\n");

    ElfReader elf_reader(source.c_str(), fd);
    elf_reader.setDumpSoFile(isDumpSoFile);

    if(!elf_reader.Load()) {
        printf("source so file is invalid\n");
        return -1;
    }

    ElfRebuilder elf_rebuilder(&elf_reader);
    if(!elf_rebuilder.Rebuild()) {
        printf("error occured in rebuilding elf file\n");
        return -1;
    }

    close(fd);

    fd = open(output.c_str(), O_WRONLY | O_BINARY | O_CREAT | O_TRUNC);
    if(fd == -1) {
        printf("output so file cannot write !!!\n");
        return -1;
    }
    write(fd, elf_rebuilder.getRebuildData(), elf_rebuilder.getRebuildSize());
    close(fd);

    printf("Done!!!\n");
    return 0;
}

void useage() {
    printf("SoFixer v0.1 author F8LEFT(currwin)\n");
    printf("Useage: SoFixer <option(s)> -s sourcefile -o generatefile\n");
    printf(" try rebuild shdr with phdr\n");
    printf(" Options are:\n");

    printf("  -d --dumpso                     Source file is dump from memory\n");
    printf("  -s --source                     Source file path\n");
    printf("  -o --output                     Generate file path\n");
    printf("  -h --help                       Display this information\n");

}