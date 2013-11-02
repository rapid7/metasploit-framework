if (!window.XMLHTTPRequest) {
  var i, ids = ["Microsoft.XMLHTTP", "Msxml2.XMLHTTP", "Msxml2.XMLHTTP.6.0", "Msxml2.XMLHTTP.3.0"];
  for (i = 0; i < ids.length; i++) {
    try {
      new ActiveXObject(ids[i]);
      window.XMLHttpRequest = function() {
        return new ActiveXObject(ids[i]);
      };
      break;
    }
    catch (e) {}
  }
}
