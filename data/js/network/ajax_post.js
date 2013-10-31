function postInfo(path, data) {
  var xmlHttp = '';
  if (window.XMLHttpRequest) {
    xmlHttp = new XMLHttpRequest();
  }
  else {
    var objs = ["Microsoft.XMLHTTP", "Msxml2.XMLHTTP", "Msxml2.XMLHTTP.4.0"];
    for (var i=0; i < objs.length; i++) {
      try {
        xmlHttp = new ActiveXObject(objs[i]);
        break;
      }
      catch (e) {}
    }
  }

  if (xmlHttp.overrideMimeType) {
    xmlHttp.overrideMimeType("text/plain; charset=x-user-defined");
  }

  xmlHttp.open('POST', path, false);
  xmlHttp.send(data);
}