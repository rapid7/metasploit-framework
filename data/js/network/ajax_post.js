function postInfo(path, data) {
  var xmlHttp = '';
  if (window.XMLHttpRequest) {
    xmlHttp = new XMLHttpRequest();
  }
  else {
    xmlHttp = new ActiveXObject("Microsoft.XMLHTTP");
  }

  if (xmlHttp.overrideMimeType) {
    xmlHttp.overrideMimeType("text/plain; charset=x-user-defined");
  }

  xmlHttp.open('POST', path, false);
  xmlHttp.send(data);
}