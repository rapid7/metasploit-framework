function postModule()
{
    var xhr=new XMLHttpRequest();
    var url="http://127.0.0.1:3000/post";
    xhr.open("GET",url,true);
    xhr.send();

    xhr.onreadystatechange = function(){
        var postJson = xhr.response;
        //var postData = JSON.parse(postJson);
        if(xhr.readyState===4 && xhr.status===200){
            var arr= Object.keys(postJson);
            for(var i=0;i<arr.length;i++)
            {

                var text=document.createElement("li");
                var myList = document.createElement('ul');

                text.textContent=arr[i];

                var post_mod =postJson[arr[i]]; 		// content inside windows,llinux
                var postmod_arr=Object.keys(post_mod);

                if(postmod_arr[i]!==0){
                    for(var j=0;j< postmod_arr.length;j++){
                        var subList=document.createElement('li');
                        subList.textContent=postmod_arr[j];
                        myList.appendChild(subList);
                    }
                }

                text.appendChild(myList);
                document.getElementById("post").appendChild(text);
            }

        } else{
            alert("Unable to Parse the request");
        }
    }
}

/*

    var post = document.getElementById("post");
    var exten = document.getElementById("exten");
    var exten_url = "127.0.0.1:3000/exten"
    var post_url = "127.0.0.1:3000/post";

    var xhr1 = new XMLHttpRequest();
    var xhr2 = new XMLHttpRequest();

    xhr1.open("GET", post_url, true);
    xhr1.send();

    xhr2.open("GET", exten_url, true);
    xhr2.send();


    xhr1.onload = function () {

            var postJson = xhr1.response;
            //var postData = JSON.parse(postJson);
            postModule(postJson);

    };

    xhr2.onload = function () {

            var extenJson = xhr2.response;
            //var extenData = JSON.parse(extenJson);
            extensionCommand(extenJson);

    };

    function postModule(postJsonObj) {
        var arr= Object.keys(postJsonObj);
        for(var i=0;i<arr.length;i++)
        {

            var text=document.createElement("li");
            var myList = document.createElement('ul');

            text.textContent=arr[i];

            var post_mod =postJsonObj[arr[i]]; 		// content inside windows,llinux
            var postmod_arr=Object.keys(post_mod);

            if(postmod_arr[i]!==0){
                for(var j=0;j< postmod_arr.length;j++){
                    var subList=document.createElement('li');
                    subList.textContent=postmod_arr[j];
                    myList.appendChild(subList);
                }
            }

            text.appendChild(myList);
            document.getElementById("post").appendChild(text);
        }
    }

    function extensionCommand(extenJsonObj) {
        var exdata = extenJsonObj.length;
        for (var i = 0; i, exdata; i++) {
            var extList = document.createElement("li");
            extList.textContent = extenJsonObj[i];
            exten.appendChild(extList);
        }
    }
*/




/*
var post=document.getElementById("post");
var exten=document.getElementById("exten");

var post_url="127.0.0.1:3000/post";
var exten_url="127.0.0.1:3000/exten";
var xhr= new XMLHttpRequest();
xhr.open("GET",post_url,true);
xhr.open("GET",exten_url,true);

xhr.send();





 function loadDoc(url,cFunction){
    xhr.onload= function(){
      if(this.readyState==4 && this.status==200){
          var JsonData=xhr.response;
          var JsonParsed=JSON.parse(JsonData);
          postModule(JsonParsed);
     //     cFunction(this);
          xhr.open("GET",post_url,true);
          xhr.send();
      }
    };

  xhr.responseType="text";
  xhr.open("GET",url,true);
  xhr.send();
}

   function postModule(xhr){
     var postText=xhr.response;
     var postJson=JSON.parse(postText);

     var android=postJson[android];
     var android_list=document.createElement("li");
     for(var i=0;i<postJson;i++)
     {

     }
    var post_list= document.createElement("li");
    var post_text= document.createTextNode('<a id="runpost" href="#">' + this.responseText + '</a>');
    post_list.appendChild(post_text);
  }

  function extension(xhr){
   var exten_list= document.createElement("li");
    var exten_text= document.createTextNode('<a id="runexten" href="#">' + this.responseText + '</a>');
    exten_list.appendChild(exten_text);
  }


*/

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
