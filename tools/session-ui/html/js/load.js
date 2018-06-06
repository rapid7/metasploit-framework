
 function loadDoc(url,cFunction){
    var xhr= new XMLHttpRequest();
    xhr.onreadystatechange= function(){
      if(this.readyState==4 && this.status==200){
          cFunction(this);
      }
    };

  xhr.open("GET",url,true);
  xhr.send(null);
}

   function postModule(xhr){
    var post_list= document.createElement("li");
    var post_text= document.createTextNode('<a id="runpost" href="#">' + this.responseText + '</a>');
    post_list.appendChild(post_text);
  }

  function Extension(xhr){
   var exten_list= document.createElement("li");
    var exten_text= document.createTextNode('<a id="runexten" href="#">' + this.responseText + '</a>');
    exten_list.appendChild(exten_text);
  }




  /*----------------- Implementation of web socket for Browser shell.---------------------*/

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

/*-----------------------------End Of Web Socket Section ------------------------*/
