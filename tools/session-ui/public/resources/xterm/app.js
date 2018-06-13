   
        
        var term = new Terminal({
            cols: 145,
            rows: 31,
            fontSize: 15,
            fontFamily: '"Menlo for Powerline", Menlo, Consolas, "Liberation Mono", Courier, monospace',
            theme: {
                foreground: '#d2d2d2',
                background: '#000000',
                cursor: '#adadad',
                black: '#000000',
                red: '#d81e00',
                green: '#5ea702',
                yellow: '#cfae00',
                blue: '#427ab3',
                magenta: '#89658e',
                cyan: '#00a7aa',
                white: '#dbded8',
                brightBlack: '#686a66',
                brightRed: '#f54235',
                brightGreen: '#99e343',
                brightYellow: '#fdeb61',
                brightBlue: '#84b0d8',
                brightMagenta: '#bc94b7',
                brightCyan: '#37e6e8',
                brightWhite: '#f1f1f0'
            }
        });
        term.open(document.getElementById('terminal'));
        term.write('\x1B[1;3;31lMeterpreter\x1B[0m $ ');
        term.write(term.html);
       let myBuffer = [];

        // This is an xterm.js instance
        term.on('key', function(key, e) {
        myBuffer.push(key);
        });

        term.on('lineFeed', function() {
        let keysEntered = myBuffer.join('');  // Or something like that
        myBuffer = [];  // Empty buffer
        });
  