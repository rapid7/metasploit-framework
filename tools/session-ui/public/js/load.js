/* When the user clicks on the button,
toggle between hiding and showing the dropdown content */

Terminal.applyAddon(fit);
let url='ws://' + window.location.host+window.location.pathname;
let ws = new WebSocket(url,['tty']);
const term = createTerminal();
setUpTermEventHandlers();
const commandHistory = [];
let historyIndex = 0;
const shellprompt = '\n\r\x1B[1;3;31mMeterpreter\x1B[0m $ '; // length = 14
let terminalContainer = document.getElementById('terminal-container');
let textDecoder = new TextDecoder(), textEncoder = new TextEncoder();

window.onresize = function(event) {
    term.fit();
};

term.prompt = function () {
    term.write('\r\n' + shellprompt );
};


function createTerminal(){
    const term = new Terminal({
        rows: calculateNumberOfTerminalRows(),
        cols: calculateNumberOfTerminalCols(),
        fontSize: 14,
        padding:1,
        termName: 'Meterpreter',
        letterSpacing: 2,
        cursorBlink: true,
        convertEol: true,
        cursorStyle: "block",
        scrollLines:2,
        fontFamily: 'monospace',
        scrollback: 10000,
        screeenKeys: true,
        tabStopWidth: 10,
        bellSound: beep(),
        useStyle : true,
        theme: {
            foreground: '#d2d2d2',
            background: '#000000',
            cursor: '#adadad',
            black: '#000000',
            allowTransparency: true
        }
    });
    term._initialized = true;
    term.isTTY = true;
    return term;
    /*
     * This measures the height of a single character using a div's height
     * and uses that to figure out how many rows can fit in about 95% of the screen
     */
    function calculateNumberOfTerminalRows() {
        let testElement = document.createElement('div');
        testElement.innerText = 'h';
        testElement.style.visibility = 'hidden';
        document.querySelector('.xterm-term-container').append(testElement);
        testElement.style.fontSize = '14px';
        let fontHeight = testElement.clientHeight + 1;
        testElement.remove();
        return Math.floor(screen.availHeight * 0.95 / fontHeight) - 2;
    }

    /*
     * This measures the width of a single character using canvas
     * and uses that to figure out how many columns can fit in about 65% (80% for mobile) of the screen
     */
    function calculateNumberOfTerminalCols(){
        const ctx = document.createElement("canvas").getContext('2d');
        ctx.font = '14px monospace';
        const fontWidth = ctx.measureText('h').width + 1;
        const screenWidth = screen.availWidth;
        return Math.floor(screenWidth * ((screenWidth > 600) ? 0.65 : 0.8) / fontWidth) + 3;
    }

}
term.prompt();
term.open(terminalContainer, true);

function setUpTermEventHandlers() {

    term.addDisposableListener('paste', function (data, ev) {
        term.write(data);
    });
    term.on('key', (key, ev) => {
        const printable = (
            !ev.altKey && !ev.altGraphKey && !ev.ctrlKey && !ev.metaKey
        );
        // OnEnter keyMap
        // TODO: This code is push empty character while traversing through command history. Fixing is required!!
        if (ev.keyCode === 13) {
            if(term.textarea.value.length === 0 && key === " "){
                term.prompt();
            }else{
                //sendMessage(term.textarea.value);
                ws.send(term.textarea.value);
                if(term.textarea.value.length !== 0){
                    historyIndex = commandHistory.push(term.textarea.value);
                }
                term.textarea.value = "";
                historyIndex = commandHistory.length;
                //term.prompt();
            }
            console.log("Command History : " + commandHistory)
        }
        // CODE FOR backspace
        // TODO Improve backspace implementation, It only works when cursor is at line's
        else if (ev.keyCode === 8) {
            // don't delete the prompt
            if (term.buffer.x > 14) {     //because length of prompt is 14
                term.write('\b \b');
            }
            const value = term.textarea.value;
            term.textarea.value = value.slice(0, value.length - 1);
            console.log("value : " + term.textarea.value);
            console.log("value.length : " + term.textarea.value.length)
        }
        // On pressing ArrowUp code
        else if (ev.keyCode === 38) {
            // traverse LinkedList and display topmost element
            if(historyIndex === 0){
                beep();
            }
            else if (historyIndex > 0) {
                showHistoryItem(--historyIndex);
                console.log(historyIndex)
            }
            console.log("Arrow Up!");
        }
        // on pressing Arrow Down
        else if (ev.keyCode === 40) {
           if(historyIndex === commandHistory.length) {
               beep();
           }
            else if (historyIndex < commandHistory.length) {
                showHistoryItem(++historyIndex);
                console.log(historyIndex)
            }
            console.log("Arrow down!")
        }
        // On pressing Arrow left
        else if (ev.keyCode === 37) {
            // TODO: Should have the ability insert element while cruising down the content.
            // use term.textarea.value.length to track track the movement of cursor
            if(term.buffer.x === 14){
                beep();
            }
            else if (term.buffer.x > 14) {     //because length of prompt is 14
                term.write('\x1b[1D');
            }
            console.log("Arrow Left");

        }
        // on pressing Arrow Right
        else if (ev.keyCode === 39) {
            // TODO: Should have the ability insert element while cruising down the content.
            // use term.textarea.value.length to track the movement of the cursor
            if(term.buffer.x > term.textarea.value.length + 13){
                beep();
            }
            else if (term.buffer.x <= term.textarea.value.length + 13) {     //because length of prompt is 14
                term.write('\x1b[1C');
            }
            console.log(term.textarea.value);
            console.log("Arrow Right");
        }

        else if (printable) {
            if (term.textarea.value.split(/\s+/).length < 2 && key !== ' ') {
                term.write(key);
            } else {
                term.write(key);
            }
        }
    });
}

// ****************** WebSocket Implementation *************************************

ws.onopen   = function(event)  {
    show("Websocket is open");
    console.log('Websocket connection opened');
    term.fit();
    term.focus();
};

ws.onerror = function(event) {
    console.log("Web Socket Error Message : " + event.data)
};

ws.onmessage = function(event) {

    //term.write(event.data.replace(/['"]+/g, ''));
    console.log(event.data.toString());
    let response = JSON.parse(event.data);
    console.log("server message : " + response);
    term.write("\n" + response);
    term.prompt();
};

ws.onclose = function(event)  {
    //term.disable();
    console.log('Websocket connection closed with code: ' + event.code);
    //term.detach(term,ws);
    show("WebSocket Closed")
};



/*--------------------------End Of Web Socket Section ------------------------*/


function showHistoryItem(index) {
    let text = commandHistory[index] === undefined ? '' : commandHistory[index];
    let i = term.buffer.x;
    while (i > 14) {
        term.write('\b \b');
        i--;
    }
    const pieces = text.split(/\s+/);
    term.write(pieces.shift());
    while (pieces.length) {
        term.write(' ' + pieces.shift());
    }
    term.textarea.value = text;
}


let sendMessage = function (message){
    localStorage.setItem("msg",message);
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(textEncoder.encode(message));
    }
};

var sendData = function (data) {
    sendMessage('0' + data);
};

function modal(val){
    document.getElementById("sidebarTitle").innerText=val;
    let xhr=new XMLHttpRequest();
    let url="/modal?script=" + val;

    xhr.onload = function(){
        let response = xhr.responseText;
        let responseData= JSON.parse(response);
        if (xhr.readyState === 4 && xhr.status === 200){
            console.log(responseData);
            document.getElementById("postname").innerText=responseData.name;
            document.getElementById("postauthor").innerText=responseData.authors[0];
            document.getElementById("postdiscription").innerText=responseData.description;
            document.getElementById("postplatform").innerText=responseData.platform;
            document.getElementById("postrank").innerText=responseData.rank;
        }
        else
            alert("Connection Failed!");
    };
    xhr.open("GET",url);
    xhr.send();

}

function executePostScript(){
    let val=document.getElementById("sidebarTitle").innerText;
    sendMessage("run post/"+val)
}

function modal2(val){
    document.getElementById("sidebarTitle2").innerText=val + " -h";
    let xhr=new XMLHttpRequest();
    let url="/modal2?command=" + val;

    xhr.onload = function(){
        let response = xhr.responseText;
        let responseData= JSON.parse(response);
        let filtered = responseData.filter(function (el) {
            return el != null;
        });
        if (xhr.readyState === 4 && xhr.status === 200){
            document.getElementById("disc").innerText=filtered;
        }
    };
    xhr.open("GET",url,true);
    xhr.send();
}


// TODO: Refactoring this code to support N number of value of a key. Right now it displays starting from single value to max. 3 values.
// i.e. "windows" : {"gather" : [checkvm, dump_link, etc]}
function postModule() {
    let xhr = new XMLHttpRequest();
    let url = "/post";
    xhr.open("GET", url,true);
    xhr.send();
    xhr.onload = function () {
        let postJson = xhr.response;
        let postData = JSON.parse(postJson);
        let count=0;
        if (xhr.readyState === 4 && xhr.status === 200) {
            let arr = Object.keys(postData);
/* Code Block for single key value hash => "aix": "hashdump" */

            let menu_1 = document.createElement("a");
            menu_1.setAttribute("class","list-group-item");
            menu_1.setAttribute("data-toggle","collapse");
            menu_1.setAttribute("aria-expanded","false");
            menu_1.innerHTML = arr[0] ;
            menu_1.setAttribute("href","#"+arr[0]);

            let menu_1sub = document.createElement("div");
            menu_1sub.setAttribute("class","collapse");
            menu_1sub.setAttribute("id",arr[0]);

            let valueSubList_1 = document.createElement("a");
            valueSubList_1.setAttribute("class", "list-group-item");
            valueSubList_1.setAttribute("data-parent", "#" + arr[0] + count);
            valueSubList_1.setAttribute("href", "#");
            valueSubList_1.setAttribute("data-toggle", "modal");
            valueSubList_1.setAttribute("data-target", "#sidebarModal");
            valueSubList_1.setAttribute("onclick", "modal(" + "\"" + arr[0] +  "/" + Object.values(postData[arr[0]]) + "\"" + ")");
            valueSubList_1.innerHTML = Object.values(postData[arr[0]]);

            menu_1sub.appendChild(valueSubList_1);
            document.getElementById("menu1").appendChild(menu_1);
            document.getElementById("menu1").appendChild(menu_1sub);

/***********************************/

            for (let i = 1; i < arr.length; i++) {
                let menu1 = document.createElement("a");
                menu1.setAttribute("class","list-group-item");
                menu1.setAttribute("data-toggle","collapse");
                menu1.setAttribute("aria-expanded","false");
                menu1.innerHTML = arr[i] ;
                menu1.setAttribute("href","#"+arr[i]);

                let menu1sub = document.createElement("div");
                menu1sub.setAttribute("class","collapse");
                menu1sub.setAttribute("id",arr[i]);

                 		// content inside windows,linux i.e. Gather, Capture

                let post_mod = postData[arr[i]];
                let postmod_key = Object.keys(post_mod);
                if (postmod_key.length !== 0) {
                    for (let j = 0; j < postmod_key.length; j++) {
                        let subList = document.createElement("a");
                        subList.setAttribute("class", "list-group-item");
                        subList.setAttribute("data-toggle", "collapse");
                        subList.setAttribute("aria-expanded", "false");
                        subList.setAttribute("href", "#" + postmod_key[j] + count);
                        subList.innerHTML = postmod_key[j];

                        let valueList = document.createElement("div");
                        valueList.setAttribute("class", "collapse");
                        valueList.setAttribute("id", postmod_key[j] + count);

                        //Content inside Gather, Capture etc

                        let value = post_mod[postmod_key[j]];
                        for (let k = 0; k < value.length; k++) {
                            let valueSubList = document.createElement("a");
                            valueSubList.setAttribute("class", "list-group-item");
                            valueSubList.setAttribute("data-parent", "#" + postmod_key[j] + count);
                            valueSubList.setAttribute("href", "#");
                            valueSubList.setAttribute("data-toggle", "modal");
                            valueSubList.setAttribute("data-target", "#sidebarModal");
                            valueSubList.setAttribute("onclick", "modal(" + "\"" + arr[i] + "/" + postmod_key[j] + "/" + value[k] + "\"" + ")");
                            valueSubList.innerHTML = value[k];
                            menu1sub.appendChild(subList);
                            valueList.appendChild(valueSubList);
                            menu1sub.appendChild(valueList);
                        }
                    }
                }
                else{continue}
                document.getElementById("menu1").appendChild(menu1);
                document.getElementById("menu1").appendChild(menu1sub);
                count++;
            }
        }
    };
}


function ExtensionCommand() {
    let xhr = new XMLHttpRequest();
    let url = "/exten";
    xhr.open("GET", url,true);
    xhr.send();

    xhr.onload = function () {
        let exten = xhr.response;
        let extenJson=JSON.parse(exten);
        let count=0;
        if (xhr.readyState === 4 && xhr.status === 200) {
            let arr = Object.keys(extenJson);
            //console.log("arr : " + arr);
            //console.log(arr);
            for (let i = 0; i < arr.length; i++) {
                let menu2 = document.createElement("a");
                menu2.setAttribute("class", "list-group-item");
                menu2.setAttribute("data-toggle", "collapse");
                menu2.setAttribute("aria-expanded", "false");
                menu2.innerHTML = arr[i];
                menu2.setAttribute("href", "#" + arr[i]);
                let menu2sub = document.createElement('div');
                menu2sub.setAttribute("class", "collapse");
                menu2sub.setAttribute("id", arr[i]);

                let exten_cmd = extenJson[arr[i]],
                    exten_keys = Object.keys(exten_cmd),
                    exten_values = Object.values(exten_cmd);
                if (exten_keys.length !== 0) {
                    if(isInt(exten_keys[i])) {
                        for (let j = 0; j < exten_keys.length; j++) {
                            let data_list = document.createElement('a');
                            data_list.setAttribute("class", "list-group-item");
                            data_list.setAttribute("data-parent", "#" + count);
                            data_list.setAttribute("href", "#");
                            data_list.setAttribute("data-toggle", "modal");
                            data_list.setAttribute("data-target", "#sidebarModal2");
                            data_list.setAttribute("onclick", "modal2(" + "\"" + exten_values[j] + "\"" + ")");
                            data_list.innerHTML = exten_values[j];
                            menu2sub.appendChild(data_list);
                        }
                    }
                    else{
                        for (let j = 0; j < exten_keys.length; j++) {
                            let subList = document.createElement("a");
                            subList.setAttribute("class", "list-group-item");
                            subList.setAttribute("data-toggle", "collapse");
                            subList.setAttribute("aria-expanded", "false");
                            subList.setAttribute("href", "#" + exten_keys[j].split(' ').join('') + count);
                            subList.innerHTML = exten_keys[j];

                            let valueList = document.createElement("div");
                            valueList.setAttribute("class", "collapse");
                            valueList.setAttribute("id", exten_keys[j].split(' ').join('') + count);

                            //Content inside Gather, Capture etc

                            let value = exten_cmd[exten_keys[j]];
                            console.log("keys : " + exten_keys[j]+" value : " + value);
                            for (let k = 0; k < value.length; k++) {
                                let valueSubList = document.createElement("a");
                                valueSubList.setAttribute("class", "list-group-item");
                                valueSubList.setAttribute("data-parent", "#" + exten_keys[j].split(' ').join('') + count);
                                valueSubList.setAttribute("href", "#");
                                valueSubList.setAttribute("data-toggle", "modal");
                                valueSubList.setAttribute("data-target", "#sidebarModal2");
                                valueSubList.setAttribute("onclick", "modal2(" + "\""+ value[k] + "\"" + ")");
                                valueSubList.innerHTML = value[k];
                                menu2sub.appendChild(subList);
                                valueList.appendChild(valueSubList);
                                menu2sub.appendChild(valueList);
                            }
                        }
                    }

                }
                else{
                    continue
                }
                document.getElementById("menu2").appendChild(menu2);
                document.getElementById("menu2").appendChild(menu2sub);
                count++;
            }
        }
        else
            alert("Unable To load Extension Command");
    };
}

function beep() {
    let snd = new  Audio("data:audio/wav;base64,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qJrx4KOQjahZxWbcZgztj2c49nKmkId44S71j0c8eV9yDK6uPRzx5X18eDvjvQ6yKo9ZSS6l//8elePK/Lf//IInrOF/FvDoADYAGBMGb7FtErm5MXMlmPAJQVgWta7Zx2go+8xJ0UiCb8LHHdftWyLJE0QIAIsI+UbXu67dZMjmgDGCGl1H+vpF4NSDckSIkk7Vd+sxEhBQMRU8j/12UIRhzSaUdQ+rQU5kGeFxm+hb1oh6pWWmv3uvmReDl0UnvtapVaIzo1jZbf/pD6ElLqSX+rUmOQNpJFa/r+sa4e/pBlAABoAAAAA3CUgShLdGIxsY7AUABPRrgCABdDuQ5GC7DqPQCgbbJUAoRSUj+NIEig0YfyWUho1VBBBA//uQZB4ABZx5zfMakeAAAAmwAAAAF5F3P0w9GtAAACfAAAAAwLhMDmAYWMgVEG1U0FIGCBgXBXAtfMH10000EEEEEECUBYln03TTTdNBDZopopYvrTTdNa325mImNg3TTPV9q3pmY0xoO6bv3r00y+IDGid/9aaaZTGMuj9mpu9Mpio1dXrr5HERTZSmqU36A3CumzN/9Robv/Xx4v9ijkSRSNLQhAWumap82WRSBUqXStV/YcS+XVLnSS+WLDroqArFkMEsAS+eWmrUzrO0oEmE40RlMZ5+ODIkAyKAGUwZ3mVKmcamcJnMW26MRPgUw6j+LkhyHGVGYjSUUKNpuJUQoOIAyDvEyG8S5yfK6dhZc0Tx1KI/gviKL6qvvFs1+bWtaz58uUNnryq6kt5RzOCkPWlVqVX2a/EEBUdU1KrXLf40GoiiFXK///qpoiDXrOgqDR38JB0bw7SoL+ZB9o1RCkQjQ2CBYZKd/+VJxZRRZlqSkKiws0WFxUyCwsKiMy7hUVFhIaCrNQsKkTIsLivwKKigsj8XYlwt/WKi2N4d//uQRCSAAjURNIHpMZBGYiaQPSYyAAABLAAAAAAAACWAAAAApUF/Mg+0aohSIRobBAsMlO//Kk4soosy1JSFRYWaLC4qZBYWFRGZdwqKiwkNBVmoWFSJkWFxX4FFRQWR+LsS4W/rFRb/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////VEFHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU291bmRib3kuZGUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMjAwNGh0dHA6Ly93d3cuc291bmRib3kuZGUAAAAAAAAAACU=");
    snd.play();
}

function isInt(value) {
    return !isNaN(value) && (function(x) { return (x | 0) === x; })(parseFloat(value))
}
function sysinfo(){
    let xhr = new XMLHttpRequest();
    let url = "/sysinfo";

    xhr.onload = function () {
        let response = xhr.responseText;
        let responseData= JSON.parse(response);
        if (xhr.readyState === 4 && xhr.status === 200) {
            document.getElementById("computer").innerText=responseData.Computer;
            document.getElementById("os").innerText=responseData.OS;
            document.getElementById("session_type").innerText=responseData.session_type;
            document.getElementById("arch").innerText=responseData.Architecture;
            document.getElementById("getuid").innerText=responseData.getuid;
        }
        else
            alert("Connection Failed!");

        };
    xhr.open("GET", url,true);
    xhr.send();
}
let show = function(el){
    return function(msg){ el.innerHTML = msg + '<br />' + el.innerHTML; }
}(document.getElementById('msgs'));



