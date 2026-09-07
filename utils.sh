#!/bin/bash
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/pragma_once/bash/import_bash.sh";
import_bash ./number.sh
import_bash ./encoding.sh

is_ptr(){
    [[ "$1" =~ ^\[.*\]$ ]]
}
is_addr_ptr(){
    [[ "$1" =~ ^\[[0-9]*x?[0-9a-f]+\]$ ]];
}
