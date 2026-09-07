#!/bin/bash
b64_alphabet="$(echo -n {A..Z} {a..z} {0..9} '+' '/' '=' | tr -d ' ')"

# Initialize variables
i=0
last_bits=""

echo "Glaudiston" | base64 | tr -d '\n' | while read -r -n1 c; do
    idx=$(expr index "$b64_alphabet" "$c")
    if [ "$idx" -eq 0 ]; then
        echo "Character '$c' not found in Base64 alphabet."
        continue
    fi

    let idx-- 
    bits=$(printf %06d "$(echo "obase=2; $idx" | bc)")
    sht=$(((i % 4) * 2))
    shbt=${bits:0:$sht}
    
    if [ -z "$last_bits" ]; then
        byte="$(( 2#$shbt ))"
    else
        byte="$(( (2#$last_bits << sht) + (2#$shbt) ))"
    fi

    # Print the decoded byte
    if [ "$i" -gt 0 ] && [ "$((i % 4))" -eq 0 ]; then
        printf "%b" "$(printf "\\x%02x" "$byte")"
    fi
    
    last_bits="$bits"
    let i++
done

# Output any final byte if needed
if [ -n "$last_bits" ]; then
    printf "%b" "$(printf "\\x%02x" "$((2#$last_bits))")"
fi
