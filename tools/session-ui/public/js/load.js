/* When the user clicks on the button,
toggle between hiding and showing the dropdown content */
document.onreadystatechange = function () {
    var state = document.readyState
    if (state == 'complete') {
        setTimeout(function(){
            document.getElementById('interactive');
            document.getElementById('load').style.visibility="hidden";
        },2000);
    }
}

function modal(val){
    document.getElementById("sidebarTitle").innerText=val;
    var xhr=new XMLHttpRequest();
    var url="/modal?script=" + val;
    xhr.open("GET",url,true);
    xhr.send();
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
                        subList.setAttribute("class","list-group-item");
                        subList.setAttribute("data-toggle","collapse");
                        subList.setAttribute("aria-expanded","false");
                        subList.setAttribute("href","#"+postmod_key[j]+count);
                        subList.innerHTML = postmod_key[j];

                        var valueList=document.createElement("div");
                        valueList.setAttribute("class","collapse");
                        valueList.setAttribute("id",postmod_key[j]+count);

                        //Content inside Gather, Capture etc

                        var value= post_mod[postmod_key[j]];
                       
                            for(var k=0;k<value.length;k++){

                                var valueSubList=document.createElement("a");
                                valueSubList.setAttribute("class","list-group-item");
                                valueSubList.setAttribute("data-parent", "#"+postmod_key[j]+count);
                                valueSubList.setAttribute("href","#");
                                valueSubList.setAttribute("data-toggle","modal");
                                valueSubList.setAttribute("data-target","#sidebarModal");
                                valueSubList.setAttribute("onclick","modal(" + "\"" + arr[i]+"/"+postmod_key[j] + "/" +value[k]+ "\"" +")");
                                valueSubList.innerHTML =  value[k] ;
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
        var extenJson = xhr.response;
        var extenData = JSON.parse(extenJson);
        if (xhr.readyState === 4 && xhr.status === 200) {
            var val = Object.values(extenData);
            for (var i = 0; i < val.length; i++) {

                var list = document.createElement("li");
                list.setAttribute("class", "active has-sub");
                var ancr = document.createElement("a");
                ancr.setAttribute("class", "js-arrow");
                ancr.setAttribute("href", "#");
                ancr.innerHTML= val[i] + "<span class='arrow'><i class='fas fa-angle-down'></i></span>" ;
                list.appendChild(ancr);
                document.getElementById("exten").appendChild(list);
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
    xhr.open("GET", url);
    xhr.send();
}





/*----------------- Implementation of web socket for Browser shell.-------------

var wsuri = "ws://127.0.0.1:3000/soc";
var output;

function init()
{
output=document.getElementById("add");
testWebSocket();
}

function testWebSocket()
{
websocket=new WebSocket(wsuri);
websocket.onopen=function(evt){ onOpen(evt) };
websocket.onclose=function(evt){ onClose(evt) };
websocket.onmessage=function(evt){ onMessage(evt) };
websocket.onerror=function(evt) { onError(evt) };

}

function onOpen(evt)
{
writeToScreen("CONNECTED !");
doSend("WebSocket rocks");
}

function onClose(evt)
{
writeToScreen("DISCONNECTED");
}

function onMessage(evt)
{
writeToScreen('<span style="color: blue;"> Response : ' + evt.data + '</span>');
websocket.close();
}

function onError(evt)
{
writeToScreen('<span style="color:red;">ERROR: </span>' + evt.data)
}

function doSend(message)
{
writeToScreen("SENT: " + message);
websocket.send(message);
}

function writeToScreen(message)
{
var pre=document.createElement("p");
pre.style.wordWrap = 'break-word';
pre.innerHTML=message;
output.appendChild(pre);
}

window.addEventListener("load",init,false)

--------------------------End Of Web Socket Section ------------------------*/
