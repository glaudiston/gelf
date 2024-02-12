import { main, genElem, extractHexAscFromRawXxd } from './framework.js';
import ELF64 from './elf64.js';

main(_ => {
	document.title = 'GELF';
	let domTree = {
	  tagName: 'DIV',
	  childs: [
	    {
	      tagName: 'INPUT',
              type: 'file',
	      events: {
		      change: function(ev){
				let file = ev.target.files[0];
				let fr = new FileReader();
				fr.addEventListener('loadend', function(o){
					let elfStruct = new ELF64(o.target.result);
					document.getElementById('elf-xxd-input').value = elfStruct.toHexDumpString();
					document.getElementById('start-addr').value = elfStruct.getStartAddr().toString(16).padStart(16,'0');
				}, false);
				fr.readAsArrayBuffer(file);
			}
	      }
	    },
	    {
	      tagName: 'TEXTAREA',
	      id: 'elf-xxd-input',
	      placeholder: 'ELF HexDump'
	    },
            { tagName: 'DIV',
	      id: 'elf-sections',
	    },
	    { tagName: 'DIV',
	      id: 'elfHeaderDiv',
	      childs: [
	        { tagName: 'INPUT',
		  id: 'start-addr'}
	      ]}
          ]
	};
	document.body.appendChild(genElem(domTree));
});
