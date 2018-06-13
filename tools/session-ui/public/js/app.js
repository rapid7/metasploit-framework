import * as Terminal from 'xterm/dist/xterm'
import * as fit from 'xterm/dist/addons/fit/fit'
require('xterm/dist/xterm.css')


		var term = new Terminal();
        term.open(document.getElementById('terminal'));
        term.write('\x1B[1;3;31lMeterpreter\x1B[0m $ ')