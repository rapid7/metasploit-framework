


/* Simple button to close terminal

<button type="button" style="font-family: sans-serif; font-size: 12px; display: block; position: fixed; border: medium none; background: rgb(34, 136, 204) none repeat scroll 0% 0%; color: rgb(255, 255, 255); padding: 5px 15px; cursor: pointer; top: 0px; right: 0px; border-radius: 0px 0px 0px 5px;">Show Info</button>
*/
        var textDecoder = new TextDecoder();
        var textEncoder = new TextEncoder();
        var terminal = document.getElementById('terminal');
        var wsUri = "";

        Terminal.applyAddon(attach);
        Terminal.applyAddon(fit);

/*    /app.js#L182 */

var openWs= function(){
    var ws=new WebSocket(wsUri);
    var sendMessage = function (message) {
        if (ws.readyState === ws.OPEN) {
            ws.send(textEncoder.encode(message));
        }
    };


    var sendData = function (data) {
        sendMessage('0' + data);
    };

    var unloadCallback = function (event) {
        var message = 'Close terminal? this will also terminate the command.';
        (event || window.event).returnValue = message;
        return message;
    };
    /* To reset the terminal

    var resetTerm = function() {
        hideModal();
        clearTimeout(reconnectTimer);
        if (ws.readyState !== WebSocket.CLOSED) {
            ws.close();
        }
        openWs();
    };
                    */
    ws.binaryType = 'arraybuffer';

    ws.onopen = function (event) {
        console.log('Websocket connection opened');
        wsError = false;

        if (typeof term !== 'undefined') {
            term.dispose();
        }

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


        term.on('resize', function (size) {
            if (ws.readyState === WebSocket.OPEN) {
                sendMessage('1' + JSON.stringify({columns: size.cols, rows: size.rows}));
            }
            setTimeout(function () {
                term.showOverlay(size.cols + 'x' + size.rows);
            }, 500);
        });

        term.on('title', function (data) {
            if (data && data !== '') {
                document.title = (data + ' | ' + title);
            }
        });

        term.on('data', sendData);

        while (terminal.firstChild) {
            terminal.removeChild(terminal.firstChild);
        }

        window.addEventListener('resize', function() {
            clearTimeout(window.resizedFinished);
            window.resizedFinished = setTimeout(function () {
                term.fit();
            }, 250);
        });
        window.addEventListener('beforeunload', unloadCallback);

        term.open(terminal, true);
        term.fit();
        term.focus();
    };
    ws.onmessage = function(event) {
        var rawData = new Uint8Array(event.data),
            cmd = String.fromCharCode(rawData[0]),
            data = rawData.slice(1).buffer;
        switch(cmd) {
            case '0':
                title = textDecoder.decode(data);
                document.title = title;
                break;
            case '1':
                var preferences = JSON.parse(textDecoder.decode(data));
                Object.keys(preferences).forEach(function(key) {
                    console.log('Setting ' + key + ': ' +  preferences[key]);
                    term.setOption(key, preferences[key]);
                });
                break;
        }
    };

    ws.onclose = function(event) {
        console.log('Websocket connection closed with code: ' + event.code);
        if (term) {
            term.off('data');
            term.off('resize');
            if (!wsError) {
                term.showOverlay('Connection Closed', null);
            }
        }
        window.removeEventListener('beforeunload', unloadCallback);
        // 1000: CLOSE_NORMAL

    };




};


if (document.readyState === 'complete' || document.readyState !== 'loading') {
    openWs();
} else {
    document.addEventListener('DOMContentLoaded', openWs);
}
