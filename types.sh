#!/bin/bash

SIZE_8BITS_1BYTE=1
SIZE_16BITS_2BYTES=2
SIZE_32BITS_4BYTES=4
SIZE_64BITS_8BYTES=8

Elf64_Half=$SIZE_16BITS_2BYTES;
Elf64_Word=$SIZE_32BITS_4BYTES;
Elf64_Xword=$SIZE_64BITS_8BYTES;
Elf64_Addr=$SIZE_64BITS_8BYTES;
Elf64_Off=$SIZE_64BITS_8BYTES;

# Used for constants hardcoded like STDOUT, STDERR and any other values known at build time.
SYMBOL_TYPE_STATIC=0;
# Runtime variables stored at memory. Unable to recover the address at built time.
SYMBOL_TYPE_DYNAMIC=1;
# Values Stored at processor register fields.
SYMBOL_TYPE_REGISTER=2;
# Instructions stored
SYMBOL_TYPE_PROCEDURE=3;

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
