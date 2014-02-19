function postInfo(path, data) {
  var xmlHttp = new XMLHttpRequest();

  if (xmlHttp.overrideMimeType) {
    xmlHttp.overrideMimeType("text/plain; charset=x-user-defined");
  }

  xmlHttp.open('POST', path, false);
  xmlHttp.send(data);
}