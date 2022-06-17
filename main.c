#include <elf.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  printf("sizeof Elf64_Shdr:\t%li\n", sizeof(Elf64_Shdr));
  printf("sizeof Elf64_Phdr:\t%li\n", sizeof(Elf64_Phdr));
  printf("sizeof Elf64_Word:\t%li\n", sizeof(Elf64_Word));
  printf("sizeof Elf64_Off:\t%li\n", sizeof(Elf64_Off));
  printf("sizeof Elf64_Addr:\t%li\n", sizeof(Elf64_Addr));
  printf("sizeof Elf64_Xword:\t%li\n", sizeof(Elf64_Xword));
  return 0;
}
