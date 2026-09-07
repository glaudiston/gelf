b64_alphabet="$(echo -n {A..Z} {a..z} {0..9} + / = | tr -d ' ')";
echo Glaudiston |
   	base64 |
   	tr -d '\n' |
   	while read -n1 c;
   	do 
		idx=$(expr index "$b64_alphabet" "$c"); 
		let idx--; 
		bits=$(printf %06d $(echo "obase=2; $idx" | bc)); 
		sht=$(((i % 4) * 2)); 
		shbt=${bits:0:$sht}; 
		if [ "$last_bits" == "" ]; 
		then byte=""; 
		else byte="$(( (2#$last_bits << sht) + ( 2#$shbt)))"; 
		fi; 
		bx=$(printf "%x" $byte ); 
		bch=$(printf "\\x$bx");
		echo -n $c;
	   	echo -n "=dec($idx),bits($bits)"; 
		let i++; 
		echo " shift($sht); shbt($shbt); bin($( printf %08d $(echo "obase=2; $idx" | bc))) ; hex($(printf "%x" $(( idx << (i%4) * 2 )) )) ; byte = [$byte]; [$(printf %x $byte)] [$bch]"; 
		last_bits=$bits ;
	done
