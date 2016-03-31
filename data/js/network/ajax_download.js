function ajax_download(oArg) {
  if (!oArg.method) { oArg.method = "GET"; }
  if (!oArg.path)   { throw "Missing parameter 'path'"; }
  if (!oArg.data)   { oArg.data = null; }

  var xmlHttp = new XMLHttpRequest();

  if (xmlHttp.overrideMimeType) {
    xmlHttp.overrideMimeType("text/plain; charset=x-user-defined");
  }

  xmlHttp.open(oArg.method, oArg.path, !!oArg.cb);

  if (oArg.cb) {
    xmlHttp.onreadystatechange = function() {
      if (xmlHttp.readyState == 4) { 
        oArg.cb.apply(this);
      }
    };

    xmlHttp.send(oArg.data);
  }
  else {
    xmlHttp.send(oArg.data);
    if (xmlHttp.readyState == 4 && xmlHttp.status == 200) {
      return xmlHttp.responseText;
    }

    return null;
  }

  return xmlHttp;
}