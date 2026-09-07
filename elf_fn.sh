#!/bin/bash
#
# This is a script with functions used to generate ELF files.
#
# see:
# - man elf
# - /usr/include/elf.h: has all information including enums
# - https://www.airs.com/blog/archives/38
# - http://www.sco.com/developers/gabi/latest/ch4.eheader.html
# - https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html
#
# we use base64 everywhere because bash does not support \x0 on strings
source "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/pragma_once/bash/import_bash.sh";
# shellcheck disable=SC2317
import_bash ./arch_detection.sh; # need to import first because it limits the other dependencies (ARCH var);
# shellcheck disable=SC2317
import_bash <<-EOF
	./logger/bash/logger.sh
	./elf_constants.sh
	./internal_functions.sh
	./types.sh
	./utils.sh
	./isa/${ARCH}/isa_register.sh
	./isa/isa_load.sh
	./elf/index.sh
	./read_code_bloc.sh
	./parse_code_line_elements.sh
	./get_symbol_addr.sh
	./get_symbol_usages.sh
	./get_b64_symbol_value.sh
	./set_symbol_value.sh
	./is_a_valid_number_on_base.sh
	./parse_data_bytes.sh
	./is_static_value.sh
	./is_hard_coded_value.sh
	./get_symbol_type.sh
	./is_internal_snippet.sh
	./is_dynamic_snippet.sh
	./get_snippets_until_line.sh
	./get_snippets_until_symbol.sh
	./is_static_data_snippet.sh
	./get_zero_data_offset.sh
	./get_current_static_data_displacement.sh
	./get_current_dynamic_data_offset.sh
	./get_sym_dyn_data_size.sh
	./is_valid_hex.sh
	./define/variable_increment.sh
	./define/variable_arg.sh
	./define/variable_read_from_file.sh
	./define/variable_from_exec.sh
	./define/concat_variable.sh
	./define/variable_from_test.sh
	./define/array_variable.sh
	./define/read_byte.sh
	./is_system_function.sh
	./is_user_function.sh
	./is_function.sh
	./is_function_call.sh
	./get_jmp_size.sh
	./define_variable_from_fn.sh
	./define_variable.sh
	./do_define.sh
	./parse_code_block_instr.sh
	./parse_code_block.sh
	./define_code_block.sh
	./conditional_call.sh
	./get_instr_offset.sh
	./snippet_write.sh
	./do_call.sh
	./do_exec.sh
	./direct_bytecode.sh
	./do_ilog10.sh
	./do_ret.sh
	./do_exit.sh
	./do_comment.sh
	./do_return.sh
	./empty_line.sh
	./invalid_code.sh
	./detect_instruction_size_from_code.sh
	./detect_static_data_size_from_code.sh
	./create_internal_ilog10_snippet.sh
	./get_internal_addr.sh
	./get_power10_addr.sh
	./create_internal_s2i_snippet.sh
	./create_internal_i2s_snippet.sh
	./create_internal_snippet.sh
	./detect_internal_dependencies.sh
	./xd.sh
	./write_elf.sh
EOF
