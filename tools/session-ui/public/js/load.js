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
        letterSpacing: 2,
        cursorBlink: true,
        convertEol: true,
        cursorStyle: "block",
        scrollLines:2,
        fontFamily: 'monospace',
        scrollback: 10000,
        screeenKeys: true,
        tabStopWidth: 10,
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
     * and uses that to figure out how many rows can fit in about 90% of the screen
     */
    function calculateNumberOfTerminalRows() {
        let testElement = document.createElement('div');
        testElement.innerText = 'h';
        testElement.style.visibility = 'hidden';
        document.querySelector('.xterm-term-container').append(testElement);
        testElement.style.fontSize = '14px';
        let fontHeight = testElement.clientHeight + 1;
        testElement.remove();
        return Math.floor(screen.availHeight * 0.9 / fontHeight) - 2;
    }

    /*
     * This measures the width of a single character using canvas
     * and uses that to figure out how many columns can fit in about 60% (80% for mobile) of the screen
     */
    function calculateNumberOfTerminalCols(){
        const ctx = document.createElement("canvas").getContext('2d');
        ctx.font = '14px monospace';
        const fontWidth = ctx.measureText('h').width + 1;
        const screenWidth = screen.availWidth;
        return Math.floor(screenWidth * ((screenWidth > 600) ? 0.5 : 0.8) / fontWidth) + 3;
    }

}
term.prompt();
term.open(terminalContainer, true);

function setUpTermEventHandlers() {

    //term.on('data', sendData);
    /*
    term.on('data', function(data) {
        //ws.send(JSON.stringify(['stdin', data]));
        term.write(data);
        ws.send(JSON.stringify(data));
    });
*/
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
                sendMessage(term.textarea.value);
                if(term.textarea.value.length !== 0){
                    historyIndex = commandHistory.push(term.textarea.value);
                }
                term.textarea.value = "";
                historyIndex = commandHistory.length;
                term.prompt();
            }
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
            // TODO Arrow up should show history of commands
            // traverse LinkedList and display topmost element
            if (historyIndex > 0) {
                showHistoryItem(--historyIndex);
                console.log(historyIndex)
            }
            console.log("Arrow Up!");
        }
        // on pressing Arrow Down
        else if (ev.keyCode === 40) {
            // TODO should traverse through history of commands
            if (historyIndex < commandHistory.length) {
                showHistoryItem(++historyIndex);
                console.log(historyIndex)
            }
            console.log("Arrow down!")
        }
        // On pressing Arrow left
        else if (ev.keyCode === 37) {
            // TODO should not go beyond prompt.
            // use term.textarea.value.length to track track the movement of cursor

            if (term.buffer.x > 14) {     //because length of prompt is 14
                term.write('\x1b[1D');
            }
            console.log("Arrow Left");
        }
        // on pressing Arrow Right
        else if (ev.keyCode === 39) {
            // TODO cursor should not go beyond key length of the text area
            // use term.textarea.value.length to track the movement of the cursor
            if (term.buffer.x <= term.textarea.length) {     //because length of prompt is 14
                //term.write('\x1b[1C');
            }
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

ws.onmessage = function(event) {
    console.log("server message : " + event.data);
    //json_msg = JSON.parse(event.data);
    //term.write(event.data);
    // term.prompt();
/*
    json_msg = JSON.parse(event.data);
    switch(json_msg[0]){
        case "stdout" :
            term.write(json_msg[1]);
            console.write("json_msg : " + json_msg[1]);
            break;
        case "disconnect" :
            term.write("\r\n\r\n[Finished... Meterpreter WebConsole]\r\n");
            break;
    }

    */
    /*
    if(event.data === 'false'){
        term.write("Invalid Command");
        term.prompt();
    }
    else{
        // if valid command, write data on terminal
        term.write(event.data.replace(/['"]+/g, ''));
        term.prompt()
    }
    */
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
    xhr.open("GET",url,true);
    xhr.send();
    xhr.onload = function(){
        console.log(xhr.responseText);
        let response = xhr.responseText;
        if (xhr.readyState === 4 && xhr.status === 200){

            document.getElementById("discription").innerText=response;

        }
    };
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
                if (postmod_key[i] !== 0) {
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
            for (let i = 0; i < arr.length; i++) {
                let menu2 = document.createElement("a");
                menu2.setAttribute("class", "list-group-item");
                menu2.setAttribute("data-toggle", "collapse");
                menu2.setAttribute("aria-expanded", "false");
                menu2.innerHTML = arr[i];
                menu2.setAttribute("href", "#" + count);
                let menu2sub = document.createElement('div');
                menu2sub.setAttribute("class", "collapse");
                menu2sub.setAttribute("id", count);
                let data = Object.values(extenJson[arr[i]]);
                // sub-commands

                if (data.length === 0) {
                    let data_list = document.createElement('a');
                    data_list.setAttribute("class", "list-group-item");
                    data_list.setAttribute("data-parent", "#" + count);
                    data_list.setAttribute("href", "#");
                    data_list.innerHTML = "No Command Available";
                    menu2sub.appendChild(data_list);
                }
                else {
                    for (let j = 0; j < data.length; j++) {
                        let data_list = document.createElement('a');
                        data_list.setAttribute("class", "list-group-item");
                        data_list.setAttribute("data-parent", "#" + count);
                        data_list.setAttribute("href", "#");
                        data_list.setAttribute("data-toggle", "modal");
                        data_list.setAttribute("data-target", "#sidebarModal2");
                        data_list.setAttribute("onclick", "modal2(" + "\"" + data[j] + "\"" + ")");
                        data_list.innerHTML = data[j];
                        menu2sub.appendChild(data_list);

                    }
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



