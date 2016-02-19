var misc_addons_detect = { };


/**
 * Detects whether the browser supports Silverlight or not
 **/
misc_addons_detect.hasSilverlight = function () {
	var found = false;

	//
	// When on IE, we can use AgControl.AgControl to actually detect the version too.
	// But this ability is specific to IE, so we fall back to just true/false response
	//
	try {
		var ax = new ActiveXObject('AgControl.AgControl');
		found = true;
	} catch(e) {}

	//
	// ActiveX didn't get anything, try looking in MIMEs
	//
	if (!found) {
		var mimes = window.navigator.mimeTypes;
		for (var i=0; i < mimes.length; i++) {
			if (/x\-silverlight/.test(mimes[i].type)) {
				found = true;
				break;
			}
		}
	}

	//
	// MIMEs didn't work either. Try navigator.
	//
	if (!found) {
		var count = navigator.plugins.length;
		for (var i=0; i < count; i++) {
			var pluginName = navigator.plugins[i].name;
			if (/Silverlight Plug\-In/.test(pluginName)) {
				found = true;
				break;
			}
		}
	}

	return found;
}

/**
 * Returns the Adobe Flash version
**/
misc_addons_detect.getFlashVersion = function () {
	var foundVersion = null;

	//
	// Gets the Flash version by using the GetVariable function via ActiveX
	//
	try {
		var ax = new ActiveXObject('ShockwaveFlash.ShockwaveFlash').GetVariable('$version').toString();
		foundVersion = ax.match(/[\d,]+/g)[0].replace(/,/g, '.')
	} catch (e) {}

	//
	// This should work fine for most non-IE browsers
	//
	if (foundVersion == null) {
		var mimes = window.navigator.mimeTypes;
		for (var i=0; i<mimes.length; i++) {
			var pluginDesc = mimes[i].enabledPlugin.description.toString();
			var m = pluginDesc.match(/Shockwave Flash [\d\.]+/g);
			if (m != null) {
				foundVersion = m[0].match(/\d.+/g)[0];
				break;
			}
		}
	}

	//
	// Detection for Windows + Firefox
	//
	if (foundVersion == null) {
		var pluginsCount = navigator.plugins.length;
		for (i=0; i < pluginsCount; i++) {
			var pluginName = navigator.plugins[i].name;
			var pluginVersion = navigator.plugins[i].version;
			if (/Shockwave Flash/.test(pluginName) && pluginVersion != undefined) {
				foundVersion = navigator.plugins[i].version;
				break;
			}
		}
	}

	return foundVersion;
}

/**
 * Returns the Java version
 **/
misc_addons_detect.getJavaVersion = function () {
	var foundVersion = null;

	//
	// This finds the Java version from Java WebStart's ActiveX control
	// This is specific to Windows
	//
	for (var i1=0; i1 < 10; i1++) {
	for (var i2=0; i2 < 10; i2++) {
	for (var i3=0; i3 < 10; i3++) {
	for (var i4=0; i4 < 10; i4++) {
		var version = String(i1) + "." + String(i2) + "." + String(i3) + "." + String(i4);
		var progId = "JavaWebStart.isInstalled." + version;
		try {
			new ActiveXObject(progId);
			return version;
		}
		catch (e) {
			continue;
		}		
	}}}}

	//
	// This finds the Java version from window.navigator.mimeTypes
	// This seems to work pretty well for most browsers except for IE
	//
	if (foundVersion == null) {
		var mimes = window.navigator.mimeTypes;
		for (var i=0; i<mimes.length; i++) {
			var m = /java.+;version=(.+)/.exec(mimes[i].type);
			if (m) {
				var version = parseFloat(m[1]);
				if (version > foundVersion) {
					foundVersion = version;
				}
			}
		}
	}

	//
	// This finds the Java version from navigator plugins
	// This is necessary for Windows + Firefox setup, but the check isn't as good as the mime one.
	// So we do this last.
	//
	if (foundVersion == null) {
		var foundJavaString = "";
		var pluginsCount = navigator.plugins.length;
		for (i=0; i < pluginsCount; i++) {
			var pluginName = navigator.plugins[i].name;
			var pluginVersion = navigator.plugins[i].version;
			if (/Java/.test(pluginName) && pluginVersion != undefined) {
				foundVersion = navigator.plugins[i].version;
				break;
			}
		}
	}

	return foundVersion;
}