class ELF64 {
	struct = {
		elfMag: {
			cid: "e_ident",
			description: "Magic bytes, identify this file as ELF format",
			type: "string",
			size: 4,
			offset: 0
		},
		eiClass: {
			description: "Processor Architecture ID",
			domain: {
				x86: "\x01",
			},
			size: 1
		},
		eiData: {
			description: "Endianess",
			size: 1
		},
		eiVersion: {
			description: ""
		}
	};
	constructor(elfArrayBuffer){
		this.elfArrayBuffer = elfArrayBuffer;
		this.dataView = new DataView(this.elfArrayBuffer);
		this.startAddr = this.dataView.getBigUint64(24, true)
	/*
	# 00-0f
	SECTION_ELF_HEADER="${ELFMAG}${EI_CLASS}${EI_DATA}${EI_VERSION}${EI_OSABI}${EI_PAD}"; # 16 bytes
	# 10-1f
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_ETYPE}${EI_MACHINE}${EI_MACHINE_VERSION}${EI_ENTRY}";
	# 20-2f
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_PHOFF}${EI_SHOFF}";
	# 30-3f
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_FLAGS}${EI_EHSIZE}${EI_PHENTSIZE}${EI_PHNUM}${EI_SHENTSIZE}${EI_SHNUM}${EI_SHSTRNDX}";
	 * */
	}
	toHexDumpString = function(){
		let fullDump = '';// '0'.padStart(8,'0') + ':';
		let lb = '';
		let s = '';
		for (let i=0; i < this.dataView.byteLength; i++){
			let isNewLine = (i % 16) == 0
			if (isNewLine){
				fullDump += lb + s + (i > 0?'\n':'') + i.toString(16).padStart(8,'0') + ':' ;
				lb = '';
				s = ' ';
			}
			if (i % 2 == 0) {
				lb += ' ';
			}
			lb += this.dataView.getUint8(i).toString(16).padStart(2,'0');
			s += String.fromCharCode(this.dataView.getUint8(i)).replace(/[^\w]/gi,'.');
		}
		if (this.dataView.byteLength > 0){ // if not full line append the remaining
			fullDump += lb;
		}
		return fullDump;
	}

	getStartAddr = function(){
		return this.startAddr
	}
}

export default ELF64;
