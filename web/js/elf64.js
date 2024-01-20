class ELF64 {
	constructor(elfArrayBuffer){
		this.elfArrayBuffer = elfArrayBuffer;
		this.dataView = new DataView(this.elfArrayBuffer);
		this.startAddr = this.dataView.getBigUint64(24, true)
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
