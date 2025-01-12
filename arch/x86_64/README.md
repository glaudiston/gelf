GELF Arch/X86-64
================
In this folder we should code everything related to x86_64 bytecode, including arch helpers, specific arch functions and linux system-calls.

In the begining it used to be one single file but after reaching almost 3k lines things need to change and from now on we should put each function in his own file.

This folder contains the source code used for GELF compilation related to x86_64 architecture.

### Assembly Language

The assembly language used by GELF is defined in the bytecode.sh script provided as part of this repository. The script have comments that demonstrates how to write x86-64 instructions in a human-readable format.

Here are some key concepts in the assembly language:

*   `mov` moves data from one register to another.
*   `cmp` compares two values and sets flags accordingly.
*   `jz`, `jae`, `jb`, `jbe`, etc. perform conditional jumps based on flag settings.
*   `add`, `sub`, `mul`, `div`, etc. perform arithmetic operations.
*   `inc`, `dec`, `add`, `sub` are used to increment or decrement a value.
*   `prefix` specifies the instruction prefix (e.g., `0F3D` for `REP MOVSB`).
*   `MODRM` specifies the opcodes, modes, and other properties of an instruction.

### Instructions

GELF uses the following instructions:

*   `MOV` moves data from one register to another.
*   `ADD` adds two values.
*   `SUB` subtracts one value from another.
*   `MUL` multiplies two values.
*   `DIV` divides one value by another.
*   `JMP` jumps unconditionally to a target address.

### Registers

GELF uses the following registers:

*   `RAX`: The accumulator register, used for arithmetic and logical operations.
*   `RBX`: The base index register, used for string indexing and other purposes.
*   `RCX`: A temporary storage register.
*   `RDX`: The data register, used for moving and manipulating data.

### Memory

GELF uses the following memory regions:

*   `DATA`: Stores initialized constants and literals.
*   `STACK`: Used to store function call stack frames and local variables.
*   `HEAP`: A pool of memory allocated by the program for its own use.
*   `TEXT`: The program code, loaded into memory as needed.

### Variables

GELF uses the following variables:

*   `$SYMBOL_TYPE_STATIC`: Indicates that a symbol is static (not relative to another symbol).
*   `$SYMBOL_TYPE_HARD_CODED`: Indicates that a symbol has a fixed address.
*   `$SYS_READ`, `$SYS_WRITE`, `$SYS_EXECVE`, etc.: System call numbers for various operations.

### Functions

GELF contains several functions:

*   `system_call_write`: Writes data to standard output using the system write function.
*   `system_call_exit`: Exits the program with a specified exit code.
*   `system_call_fork`: Creates a new process by duplicating the current process.
*   `system_call_pipe`: Creates a pipe for inter-process communication.
*   `system_call_wait4`: Waits for an input and returns its value.

For more information about using GELF, see the [GELF documentation](https://github.com/glaudiston/gelf).

### Contributing to GELF

If you'd like to contribute to GELF, please follow these steps:

1.  **Fork the repository**: Clone this repository and create a new fork on GitHub or other Git service.
2.  **Make changes**: Modify the code as needed for your use case.
3.  **Test your changes**: Run tests using `make check` to verify that your changes work correctly.

### License

GELF is licensed under the [MIT License](https://github.com/mrcheek/gelf/blob/master/LICENSE).
