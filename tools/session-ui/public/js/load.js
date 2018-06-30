/* When the user clicks on the button,
toggle between hiding and showing the dropdown content */

function filterFunction() {
  var input, filter, ul, li, a, i;
  input = document.getElementById("Search");
  filter = input.value.toLocaleString();
  div = document.getElementById("menu1");
  a = div.getElementsByTagName("a");
  for (i = 0; i < a.length; i++) {
    if (a[i].innerHTML.toLowerCase().indexOf(filter) > -1) {
       a[i].style.display = "";
    } else {
      a[i].style.display = "none";
    }
  }
}


function modal(){
    //alert("Dhawan was here");
}



function postModule() {
    var xhr = new XMLHttpRequest();
    var url = "http://127.0.0.1:3000/post";
    xhr.open("GET", url);
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
                                valueSubList.setAttribute("id",arr[i]+"/"+postmod_key[j] + "/" +value[k]);
                                //valueSubList.setAttribute("id","sidebar");
                                valueSubList.setAttribute("onclick","modal(); this.onclick=null;");
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
    }
}



function ExtensionCommand() {
    var xhr2 = new XMLHttpRequest();
    var url2 = "http://127.0.0.1:3000/exten";
    xhr2.open("GET", url2);
    xhr2.send();

    xhr2.onload = function () {
        var extenJson = xhr2.response;
        var extenData = JSON.parse(extenJson);
        if (xhr2.readyState === 4 && xhr2.status === 200) {
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
    }
}


function sysinfo(){
    var xhr3 = new XMLHttpRequest();
    var url3 = "http://127.0.0.1:3000/sysinfo";
    xhr3.open("GET", url3);
    xhr3.send();

    xhr3.onload = function () {
        var sysinfoJson =  JSON.parse(xhr3.response);
        
        if (xhr3.readyState === 4 && xhr3.status === 200) {
            document.getElementById("sysname").innerHTML=sysinfoJson.systemName;
            document.getElementById("ip").innerHTML=sysinfoJson.ip;
            document.getElementById("os").innerHTML=sysinfoJson.os;
            document.getElementById("getuid").innerHTML=sysinfoJson.getuid;
            document.getElementById("whoami").innerHTML=sysinfoJson.whoami;

        }
        else
            alert("Connection Failed!");

        }

}



function postResponse(){

}

function extenCmdResponse(){

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
