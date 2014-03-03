function postInfo(path, data) {
  var xmlHttp = new XMLHttpRequest();

  if (xmlHttp.overrideMimeType) {
    xmlHttp.overrideMimeType("text/plain; charset=x-user-defined");
  }

  xmlHttp.open('POST', path, false);
  xmlHttp.send(data);
}

function postForm(path, data) {
  var set = function(obj, attr, val) {
    if (obj.setAttribute) { obj.setAttribute(attr, val); }
    else { obj[attr] = val; }
  }

  var form = document.createElement('form');
  set(form, 'method', 'POST');
  set(form, 'action', path);

  var input;
  for (var i in data) {
    input = document.createElement('input')
    set(input, 'type', 'hidden');
    set(input, 'name', i);
    set(input, 'value', data[i]);
    form.appendChild(input);
  }

  form.style.display = 'none';
  document.body.appendChild(form);
  form.submit();
}