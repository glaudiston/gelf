#!/bin/bash

Elf64_Half=$SIZE_16BITS_2BYTES;
Elf64_Word=$SIZE_32BITS_4BYTES;
Elf64_Xword=$SIZE_64BITS_8BYTES;
Elf64_Addr=$SIZE_64BITS_8BYTES;
Elf64_Off=$SIZE_64BITS_8BYTES;

# receives the type as first argument
# and the value as second argument
# and return the hex string representation
# using the current endianess
print_with_type()
{
	printEndianValue "${2}" "${1}";
}

print_Elf64_Half()
{
	print_with_type Elf64_Half "$1"
}
