window.addons_detect = { };

/**
 * Returns the version of Microsoft Office. If not found, returns null.
 **/
window.addons_detect.getMsOfficeVersion = function () {
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