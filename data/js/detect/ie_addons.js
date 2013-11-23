window.ie_addons_detect = { };

/**
 * Returns true if this ActiveX is available, otherwise false.
 * Grabbed this directly from browser_autopwn.rb
 **/
window.ie_addons_detect.hasActiveX = function (axo_name, method) {
  var axobj = null;
  if (axo_name.substring(0,1) == String.fromCharCode(123)) {
    axobj = document.createElement("object");
    axobj.setAttribute("classid", "clsid:" + axo_name);
    axobj.setAttribute("id", axo_name);
    axobj.setAttribute("style", "visibility: hidden");
    axobj.setAttribute("width", "0px");
    axobj.setAttribute("height", "0px");
    document.body.appendChild(axobj);
    if (typeof(axobj[method]) == 'undefined') {
      var attributes = 'id="' + axo_name + '"';
      attributes += ' classid="clsid:' + axo_name + '"';
      attributes += ' style="visibility: hidden"';
      attributes += ' width="0px" height="0px"';
      document.body.innerHTML += "<object " + attributes + "></object>";
      axobj = document.getElementById(axo_name);
    }
  } else {
    try {
      axobj = new ActiveXObject(axo_name);
    } catch(e) {
      // If we can't build it with an object tag and we can't build it
      // with ActiveXObject, it can't be built.
      return false;
    };
  }
  if (typeof(axobj[method]) != 'undefined') {
    return true;
  }

  return false;
};

/**
 * Returns the version of Microsoft Office. If not found, returns null.
 **/
window.ie_addons_detect.getMsOfficeVersion = function () {
  var version;
  var types = new Array();
  for (var i=1; i <= 5; i++) {
    try {
      types[i-1] = typeof(new ActiveXObject("SharePoint.OpenDocuments." + i.toString()));
    }
    catch (e) {
      types[i-1] = null;
    }
  }

  if (types[0] == 'object' && types[1] == 'object' && types[2] == 'object' &&
      types[3] == 'object' && types[4] == 'object')
  {
    version = "2012";
  }
  else if (types[0] == 'object' && types[1] == 'object' && types[2] == 'object' &&
           types[3] == 'object' && types[4] == null)
  {
    version = "2010";
  }
  else if (types[0] == 'object' && types[1] == 'object' && types[2] == 'object' &&
           types[3] == null && types[4] == null)
  {
    version = "2007";
  }
  else if (types[0] == 'object' && types[1] == 'object' && types[2] == null &&
           types[3] == null && types[4] == null)
  {
    version = "2003";
  }
  else if (types[0] == 'object' && types[1] == null && types[2] == null &&
           types[3] == null && types[4] == null)
  {
    // If run for the first time, you must manullay allow the "Microsoft Office XP"
    // add-on to run. However, this prompt won't show because the ActiveXObject statement
    // is wrapped in an exception handler.
    version = "xp";
  }
  else {
    version = null;
  }

  return version;
}