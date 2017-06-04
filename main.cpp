#include <iostream>
#include <io.h>
#include <fcntl.h>
#include "ElfReader.h"

using namespace std;

int main() {
    auto fd = open("F:\\CodeSrc\\CLion\\soFixer\\res\\libFShell.so", O_RDONLY | O_BINARY);
    if(fd == -1) {
        printf("source so file cannot found!!!\n");
        return -1;
    }
    ElfReader elf_reader("libFShell.so", fd);
    if(!elf_reader.Load()) {
        return -1;
    }
    // TODO try rebuild so information
    cout << "Hello, World!" << endl;
    return 0;
}