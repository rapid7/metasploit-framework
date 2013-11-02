if (!window.XMLHTTPRequest) {
  var idx, activeObjs = ["Microsoft.XMLHTTP", "Msxml2.XMLHTTP", "Msxml2.XMLHTTP.6.0", "Msxml2.XMLHTTP.3.0"];
  for (idx = 0; idx < activeObjs.length; idx++) {
    try {
      new ActiveXObject(activeObjs[idx]);
      window.XMLHttpRequest = function() {
        return new ActiveXObject(activeObjs[idx]);
      };
      break;
    }
    catch (e) {}
  }
}
