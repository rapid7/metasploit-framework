function postForm(path, data) {
  window.form_id = window.form_id || 0;

  var _set = function(obj, attr, val) {
    if (obj.setAttribute) { obj.setAttribute(attr, val); }
    else { obj[attr] = val; }
  }

  var formEl = document.createElement('form');
  _set(formEl, 'method', 'POST');
  _set(formEl, 'action', path);

  var elem;
  for (var idx in data) {
    elem = document.createElement('input')
    _set(elem, 'type', 'hidden');
    _set(elem, 'name', idx);
    _set(elem, 'value', data[idx]);
    formEl.appendChild(elem);
  }

  formEl.style.display = 'none';
  document.body.appendChild(formEl);
  formEl.submit();
}
