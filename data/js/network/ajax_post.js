function postInfo(path, data, cb) {
  var xmlHttp = new XMLHttpRequest();

  if (xmlHttp.overrideMimeType) {
    xmlHttp.overrideMimeType("text/plain; charset=x-user-defined");
  }

  xmlHttp.open('POST', path, !!cb);

  if (cb) {
    xmlHttp.onreadystatechange = function() {
      if (xmlHttp.readyState == 4) { cb.apply(this, arguments); }
    };
  }

  xmlHttp.send(data);
  return xmlHttp;
}
