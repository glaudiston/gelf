let genElem = (o, p) => {
		let dom = document.createElement(o.tagName);
		Object.keys(o).forEach( k => dom.setAttribute(k, o[k]) );
		let hiddenKeys = [ 'tagname','placeholder','childs','events' ];
		hiddenKeys.forEach(k => dom.removeAttribute(k));
		if ( 'events' in o ){
			Object.keys(o.events).forEach(k => dom.addEventListener(k, o.events[k]));
		}
		if ( 'childs' in o ){
			o.childs.forEach(el => dom.appendChild(genElem(el, o)));
		}
		return dom;
	};

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
	return hexonly;
}
function parseRawXxd(rawXxdText){
	b = (lineHex =>
  new Uint8Array(lineHex.match(/.{1,2}/g).map(byte => {console.log(byte);return parseInt(byte, 16)})))(lineHex);
	return b;
}

function main(f){window.addEventListener('load', f);}
export { main, genElem, extractHexAscFromRawXxd };
