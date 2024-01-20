import ELF64 from './elf64.js';
function extractHexAscFromRawXxd(rawXxdText){
	let rawXxdLines = rawXxdText.split('\n');
	let hexonly = "";
	for (let i=0; i<rawXxdLines.length; i++){
		let lineBlocks = rawXxdLines[i].split(' ');
		let lineHex=""
		for (let j=0; j<lineBlocks.length; j++){
			if (j<1||j>8) {
				continue;
			}
			lineHex += lineBlocks[j]
		}
		hexonly += lineHex;
	}
	return hexonly
}
function parseRawXxd(rawXxdText){
	b = (lineHex =>
  new Uint8Array(lineHex.match(/.{1,2}/g).map(byte => {console.log(byte);return parseInt(byte, 16)})))(lineHex);
	return b;
}
window.addEventListener('load', _ => {
	document.title = 'GELF';
	let felf = document.createElement('input');
	felf.setAttribute('type', 'file');
	felf.addEventListener('change', function(ev){
		let file = ev.target.files[0];
		let fr = new FileReader();
		fr.addEventListener('loadend', function(o){
			let elfStruct = new ELF64(o.target.result);
			document.getElementById('elf-xxd-input').value = elfStruct.toHexDumpString();
			document.getElementById('start-addr').value = elfStruct.getStartAddr().toString(16).padStart(16,'0');
		}, false);
		fr.readAsArrayBuffer(file);
	});
	let divInput = document.createElement('div');
	divInput.appendChild(felf);
	document.body.appendChild(divInput);
	let ta = document.createElement('textarea');
	ta.setAttribute('id', 'elf-xxd-input');
	ta.setAttribute('placeholder', 'ELF HexDump');
	divInput.appendChild(ta);
	let elfSections = document.createElement('div');
	elfSections.setAttribute('id', 'elf-sections');
	document.body.appendChild(elfSections);
	let elfHeaderDiv = document.createElement('div')
	elfHeaderDiv.setAttribute('id', 'elfHeaderDiv');
	let startAddr = document.createElement('input');
	startAddr.setAttribute('id','start-addr');
	elfHeaderDiv.appendChild(startAddr);
	let preHeader = document.createElement('pre');
	preHeader.setAttribute('class', 'elf-header');
	//preHeader.innerText = elf64.elfHeader.HexDump();
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
	elfHeaderDiv.appendChild(preHeader);
	document.body.appendChild(elfHeaderDiv);
})
