/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.i18n.common");
dojo.require("dojo.lang");

dojo.require("dojo.experimental");
dojo.experimental("dojo.i18n.common");


/**
 * Gets a reference to a hash containing the localization for a given bundle in a package, matching the specified
 * locale.  Bundle must have already been loaded by dojo.requireLocalization() or by a build optimization step.
 *
 * @param modulename package in which the bundle is found
 * @param bundlename the filename in the directory structure without the ".js" suffix
 * @param locale the variant to load (optional).  By default, the locale defined by the
 *   host environment: dojo.locale
 * @return a hash containing name/value pairs.  Throws an exception if the bundle is not found.
 */
dojo.i18n.getLocalization = function(modulename, bundlename, locale /*optional*/){
	locale = dojo.normalizeLocale(locale);

	// look for nearest locale match
	var elements = locale.split('-');
	var bundle = dojo.hostenv.findModule([modulename,"_nls",bundlename].join('.'), true);

	for(var i = elements.length; i > 0; i--){
		var loc = elements.slice(0, i).join('-');
		if(bundle[loc]){
			return bundle[loc];
		}
	}

	if(bundle[dojo.fallback_locale]){
		return bundle[dojo.fallback_locale];
	}

	dojo.raise("Bundle not found " + [modulename,"_nls",bundlename,locale].join('.'));
};

/**
 * Is the language read left-to-right?  Most exceptions are for middle eastern languages.
 *
 * @param locale a string representing the locale.  By default, the locale defined by the
 *   host environment: dojo.locale
 * @return true if language is read left to right; false otherwise
 */
dojo.i18n.isLTR = function(locale /*optional*/){
	var lang = dojo.normalizeLocale(locale).split('-')[0];
	var RTL = {ar:true,fa:true,he:true,ur:true,yi:true};
	return !RTL[lang];
}
