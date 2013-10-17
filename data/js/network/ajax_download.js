function ajax_download(oArg) {
  method = oArg.method;
  path   = oArg.path;
  data   = oArg.data;

  if (method == undefined) { method = "GET"; }
  if (method == path)      { throw "Missing parameter 'path'"; }
  if (data   == undefined) { data = null; }

  if (window.XMLHttpRequest) {
    xmlHttp = new XMLHttpRequest();
  }
  else {
    xmlHttp = new ActiveXObject("Microsoft.XMLHTTP");
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