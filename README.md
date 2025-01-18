Gelf - What is this?
====================
This started as a playground for elf related stuff. I created a bash script to generate a tiny working elf file. Just using bash. Useless for anything else than learn how elf files work. But as it grows up started to look like a compiler. Then I started to define my own source file syntax. Maybe some day I can call it my own programming language. For now it is just a prototype.

In early tests it did work on native linux `x86_64` and in a `aarch64`(osx, using ubuntu within docker container). Currently it is only working on `x86_64`. I pretend to update the `aarch64` latter. But first I want to bootstrap it in `x86_64` without using bash anymore.

If you want to play with it clone the repo and try the `make check`. it will run the tests defined in `tests.sh` and output the binary and temp build files on the `test` directory.


ELF
===
Executable and Linkable Format(ELF) are the format used in all linux executables and libraries.

This repo is my try to write them from scratch. For fun and learning.

Debugging
=========
I did created a very simple debugger. Look at makefile. And you can use gdb to debug the execution. Here some tips
* Use objdump -x to get the start address
put a break point at the start address:
* `br *0x010078`
* use si to step each instruction
* you can move the program counter to read any virtual address by using:
* `set $pc=0x00010168`
Print string at some address:
```
(gdb) p/x ($rdi)
$33 = 0x1013e
(gdb) x/s 0x1013e
0x1013e:        "sample-code.gg"
```
* `argc` is `$rsp`
```
(gdb) print *((int*)$rsp)
```
* when not in first backtrace, after a call like functions or procedures `argv` is `$rsp + 8`
```
(gdb) print *((char**)($rsp + 8))
```
after copy to a mem address `(mov %rsp, *0x000100b6; # 48892425b6000100)`
```
(gdb) p *(void**)(*(void**)0x0100b6+8)
$43 = (void *) 0x3
(gdb) p *(char**)(*(void**)0x0100b6+16)
$44 = 0x7fffffffe6ff "/home/glaudiston/src/gelf/tests/test_arg_count.elf"
(gdb) p *(char**)(*(void**)0x0100b6+24)
$45 = 0x7fffffffe732 "abc"
(gdb) p *(char**)(*(void**)0x0100b6+32)
$46 = 0x7fffffffe736 "def"
```

References
==========
There is some refs on the code. Read it.
```
https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
https://anee.me/reversing-an-elf-from-the-ground-up-4fe1ec31db4a
https://reverseengineering.stackexchange.com/questions/1992/what-is-plt-got/1993#1993?newreg=360ad3611f2041ed84fa064d413f5de1
https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html
```

# What should be a nice language
Maybe someday this can be a new lang... then here I go with some notes about it
- profiling/telemetry oriented
- debugging oriented
- binary updatable at real time
- high level user friendly interface
- allowing automation / text mode control
- portable, but what if emulated in any env ?
- what if a language can detect the target algorithm and suggest the best one ?

ASM
===
To discover bytecode one good way is create an asm file with the instruction, compile it and use ld with the --oformat binary:
```
echo "mov %r8, %r10" | as -al -o /dev/null -
GAS LISTING  			page 1


   1 0000 4D89C2   	mov %r8,%r10
```
to disasm a bytecode to the asm instruction:
```
echo -ne "4889c2" | xxd --ps -r | ndisasm -b 64 -
00000000  4889C2            mov rdx,rax
```

Current test status:
```
./tests.sh
 - test_sys_exit_code	...PASS 
 - test_arg_count	...PASS 
 - test_sys_write_hard_coded_value	...PASS 
 - test_hello_world	...PASS 
 - test_custom_bytecode	...PASS 
 - test_exec	...PASS 
 - test_hello_world_base64	...PASS 
 - test_exec_with_static_args	...PASS 
 - test_fn	...PASS 
 - test_read_virtual_file	...PASS 
 - test_read_text_file	...PASS 
 - test_concat_static_symbols	...PASS 
 - test_condition	...PASS 
 - test_sys_write_out_arg	...PASS 
 - test_sys_geteuid	...PASS 
 - test_s2i	...PASS ;PASS ;
 - test_loop	...PASS 
 - test_exec_capture_stdout	...PASS 
 - test_start_code	...PASS 
 - test_arch_x86_64	...   - arch/x86_64/add_test.sh	...PASS 
   - arch/x86_64/cmp_test.sh	...PASS 
   - arch/x86_64/mov_test.sh	...PASS 
   - arch/x86_64/mul_test.sh	...PASS 
   - arch/x86_64/sub_test.sh	...PASS 
 - test_exec_concat	...PASS 
 - test_recursive_call	...PASS 
 - test_check_var_is_empty	...PASS ;PASS ;
 - test_ilog10	...n=5...PASS 
n=18...PASS 
n=184...PASS 
n=1384...PASS 
n=28952...PASS 
n=274872...PASS 
n=2428727...PASS 
n=10871242...PASS 
 - test_concat_dyn_symbols	...PASS 
 - test_exec_with_input_args	...PASS 
 - test_concat_dyn_stat_symbols	...PASS 
 - test_concat_stat_dyn_symbols	...PASS ;PASS ;
 - test_i2s	...PASS ;PASS ;
 - test_numeric_str	...PASS ;PASS ;PASS ;
 - test_fn_args	...PASS 
 - test_recursive_exec_fib	...PASS 

Resume:
	Test functions:	32
	Passed:	43
	Failed:	0

some test functions have multiple subtests
```
