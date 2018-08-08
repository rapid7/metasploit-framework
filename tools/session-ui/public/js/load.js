/* When the user clicks on the button,
toggle between hiding and showing the dropdown content */



var url='ws://' + window.location.host+window.location.pathname;
var ws = new WebSocket(url);


var terminalContainer = document.getElementById('terminal-container');
Terminal.applyAddon(fit);
var url='ws://' + window.location.host+window.location.pathname;
var textDecoder = new TextDecoder(), textEncoder = new TextEncoder(),term;


var show = function(el){
    return function(msg){ el.innerHTML = msg + '<br />' + el.innerHTML; }
}(document.getElementById('msgs'));


ws.onopen    = function(event)  {
    show("Websocket is open");
    console.log('Websocket connection opened');

    var term = new Terminal({
        cols: 110,
        rows: 40,
        fontSize: 15,
        padding:1,
        letterSpacing: 2,
        cursorBlink: true,
        cursorStyle: "block",
        scrollLines:2,
        fontFamily: '"Menlo for Powerline", Menlo, Consolas, "Liberation Mono", Courier, monospace',
        theme: {
            foreground: '#d2d2d2',
            background: '#000000',
            cursor: '#adadad',
            black: '#000000',
        }
    });


    window.addEventListener('resize', function() {
        clearTimeout(window.resizedFinished);
        window.resizedFinished = setTimeout(function () {
            term.fit();
        }, 250);
    });
    buffer=[];

    var shellprompt = '\n\r\x1B[1;3;31mMeterpreter\x1B[0m $ ';
    term.prompt = function () {
        term.write('\r\n' + shellprompt);
    };

    term.open(terminalContainer, true);
    term.prompt();
    console.log(term.buffer);

    term.addDisposableListener('key', function (key, ev) {
        var printable = (
            !ev.altKey && !ev.altGraphKey && !ev.ctrlKey && !ev.metaKey
        );


        if (ev.keyCode === 13) {

            if(buffer.join("").length === 0){
                buffer.push(key);
                term.prompt();
            }
            else if(buffer.join("") === 'clear'){
                buffer.push(key);
                term.clear();
                term.prompt()
            }

            else{
                sendMessage(buffer.join(""));
                buffer.length=0;
                term.prompt();
            }

        }

        else if (ev.keyCode === 8) {
            console.log(term.buffer);
            if (term.x > 13) {
                term.write('\b \b');
            }
            //console.log("not working")
            //term.write('\b \b');
        } else if (printable) {
            buffer.push(key);
            term.write(key);
        }
    });

    term.addDisposableListener('paste', function (data, ev) {
        term.write(data);
    });

    term.fit();
    term.focus();


    ws.onclose   = function()  {
        term.disable();
        show("WebSocket Closed")
    };

    ws.onmessage = function(event) {
        if(event.data === 'false'){
            term.write("Invalid Command");
            term.prompt();
        }
        else{
            term.write(event.data.replace(/['"]+/g, ''));
            term.prompt()
        }

    };

};

var sendMessage = function (message){
    localStorage.setItem("msg",message);
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(textEncoder.encode(message));
    }
};




function modal(val){
    document.getElementById("sidebarTitle").innerText=val;
    var xhr=new XMLHttpRequest();
    var url="/modal?script=" + val;

    xhr.onload = function(){
        var response = xhr.responseText;
        var responseData= JSON.parse(response);
        if (xhr.readyState === 4 && xhr.status === 200){

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
    var val=document.getElementById("sidebarTitle").innerText;
    console.log("run post/"+val);
    sendMessage("run post/"+val)
}


function modal2(val){
    document.getElementById("sidebarTitle2").innerText=val + " -h";
    var xhr=new XMLHttpRequest();
    var url="/modal2?command=" + val;
    console.log(val);
    xhr.open("GET",url,true);
    xhr.send();
    xhr.onload = function(){
        var response = xhr.responseText;
        console.log(response);
        if (xhr.readyState === 4 && xhr.status === 200){

            document.getElementById("discription").innerText=response;

        }
    };

}

function postModule() {
    var xhr = new XMLHttpRequest();
    var url = "/post";
    xhr.open("GET", url,true);
    xhr.send();

    xhr.onload = function () {
        var postJson = xhr.response;
        var postData = JSON.parse(postJson);
        var count=0;
        if (xhr.readyState === 4 && xhr.status === 200) {
            var arr = Object.keys(postData);
            for (var i = 0; i < arr.length; i++) {
                var menu1 = document.createElement("a");
                menu1.setAttribute("class","list-group-item");
                menu1.setAttribute("data-toggle","collapse");
                menu1.setAttribute("aria-expanded","false");
                menu1.innerHTML = arr[i] ;
                menu1.setAttribute("href","#"+arr[i]);
                var menu1sub = document.createElement("div");
                menu1sub.setAttribute("class","collapse");
                menu1sub.setAttribute("id",arr[i]);

                 		// content inside windows,linux i.e. Gather, Capture


                var post_mod = postData[arr[i]];
                var postmod_key = Object.keys(post_mod);

                if (postmod_key[i] != 0) {
                    for (var j = 0; j < postmod_key.length; j++) {
                        var subList = document.createElement("a");
                        subList.setAttribute("class", "list-group-item");
                        subList.setAttribute("data-toggle", "collapse");
                        subList.setAttribute("aria-expanded", "false");
                        subList.setAttribute("href", "#" + postmod_key[j] + count);
                        subList.innerHTML = postmod_key[j];

                        var valueList = document.createElement("div");
                        valueList.setAttribute("class", "collapse");
                        valueList.setAttribute("id", postmod_key[j] + count);

                        //Content inside Gather, Capture etc

                        var value = post_mod[postmod_key[j]];

                        for (var k = 0; k < value.length; k++) {
                            var valueSubList = document.createElement("a");
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
    var xhr = new XMLHttpRequest();
    var url = "/exten";
    xhr.open("GET", url);
    xhr.send();

    xhr.onload = function () {
        var exten = xhr.response;
        var extenJson=JSON.parse(exten);
        var count=0;
        if (xhr.readyState === 4 && xhr.status === 200) {
            var arr = Object.keys(extenJson);
            console.log(extenJson);
            for (var i = 0; i < arr.length; i++) {
                var menu2 = document.createElement("a");
                menu2.setAttribute("class", "list-group-item");
                menu2.setAttribute("data-toggle", "collapse");
                menu2.setAttribute("aria-expanded", "false");
                menu2.innerHTML = arr[i];

                menu2.setAttribute("href", "#" + count);

                var menu2sub = document.createElement('div');
                menu2sub.setAttribute("class", "collapse");
                menu2sub.setAttribute("id", count);

                var data = Object.values(extenJson[arr[i]]);
                // sub-commands

                if (data.length === 0) {
                    var data_list = document.createElement('a');
                    data_list.setAttribute("class", "list-group-item");
                    data_list.setAttribute("data-parent", "#" + count);
                    data_list.setAttribute("href", "#");
                    data_list.innerHTML = "No Command Available";
                    menu2sub.appendChild(data_list);
                }
                else {
                    for (var j = 0; j < data.length; j++) {
                        var data_list = document.createElement('a');
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
    var xhr = new XMLHttpRequest();
    var url = "/sysinfo";

    xhr.onload = function () {
        var response = xhr.responseText;
        var responseData= JSON.parse(response);
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


/*--------------------------End Of Web Socket Section ------------------------*/



/*
(function(){
        var show = function(el){
            return function(msg){ el.innerHTML = msg + '<br />' + el.innerHTML; }
            }(document.getElementById('msgs'));

        var ws       = new WebSocket('ws://' + window.location.host+window.location.pathname,['tty']);
        ws.onopen    = function()  {
                show("Websocket is open")
            };
        ws.onclose   = function()  {
            show("WebSocket Closed")
            };
        ws.onmessage = function(m) {
            show('websocket message: ' +  m.data);
        };

        var sender = function(f){
            var input     = document.getElementById('input');
            input.onclick = function(){ input.value = "" };
            f.onsubmit    = function(){
                ws.send(input.value);
                input.value = "send a message";
                return false;
                }
                }(document.getElementById('form'));
        })();

*************************************************************************************************************

var term = new Terminal({
    cols: 170,
    rows: 43,
    fontSize: 15,
    letterSpacing: 2,
    cursorBlink: true,
    cursorStyle: "block",
    fontFamily: '"Menlo for Powerline", Menlo, Consolas, "Liberation Mono", Courier, monospace',
    theme: {
        foreground: '#d2d2d2',
        background: '#000000',
        cursor: '#adadad',
        black: '#000000',
    }
});
Terminal.applyAddon(fit);
var mybuf=[];
term.open(document.getElementById('terminal-container'));
term.write("\n")
term.write('\n\r\x1B[1;3;31mMeterpreter\x1B[0m $ ');
term.on('key',(key,ev)=>{
    term.write(key);
    mybuf.push(key);
    console.log(key.charCodeAt((0)));
    if(key.charCodeAt(0)===13){
        term.write('\n\r\x1B[1;3;31mMeterpreter\x1B[0m $ ');
        console.log(mybuf.join(""));
    }
    if(key.charCodeAt(0) === 127){
        term.write("\b \b")
    }
    if(key.charCodeAt(0) ===12){

        term.clear()
    }

});
term.fit();



 */

