function ajax_download(oArg) {
  var method = oArg.method;
  var path   = oArg.path;
  var data   = oArg.data;

  if (method == undefined) { method = "GET"; }
  if (method == path)      { throw "Missing parameter 'path'"; }
  if (data   == undefined) { data = null; }

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

  xmlHttp.open(method, path, false);
  xmlHttp.send(data);
  if (xmlHttp.readyState == 4 && xmlHttp.status == 200) {
    return xmlHttp.responseText;
  }
  return null;
}