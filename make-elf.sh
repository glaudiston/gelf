#!/bin/bash
#
# depends on:
# - .elf_fn.sh (github.com/glaudiston/elf)
# - base64 (gnu-coreutils)
#

. elf_fn.sh

instructions="";
instructions="${instructions}\nwrite $(echo -n "Hello" | base64 -w0)";
instructions="${instructions}\nwrite $(echo " World" | base64 -w0)";
instructions="${instructions}\nwrite $(echo -e " By Glaudiston" | base64 -w0)";
instructions="${instructions}\nexit 0";

write_elf elf "${instructions}";
