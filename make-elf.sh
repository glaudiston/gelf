#!/bin/bash

. elf_fn.sh

instructions="write This does nothing but it is a valid elf that print this message =D"

write_elf elf "${instructions}"
