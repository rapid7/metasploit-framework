function postForm(path, data) {
  var _set = function(obj, attr, val) {
    if (obj.setAttribute) { obj.setAttribute(attr, val); }
    else { obj[attr] = val; }
  }

  var form = document.createElement('form');
  _set(form, 'method', 'POST');
  _set(form, 'action', path);

  var input;
  for (var idx in data) {
    input = document.createElement('input')
    _set(input, 'type', 'hidden');
    _set(input, 'name', idx);
    _set(input, 'value', data[idx]);
    form.appendChild(input);
  }

  form.style.display = 'none';
  document.body.appendChild(form);
  form.submit();
}