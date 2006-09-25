/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

//Semicolon is for when this file is integrated with a custom build on one line
//with some other file's contents. Sometimes that makes things not get defined
//properly, particularly with the using the closure below to do all the work.
;(function(){
	//Don't do this work if dojo.js has already done it.
	if(typeof dj_usingBootstrap != "undefined"){
		return;
	}

	var isRhino = false;
	var isSpidermonkey = false;
	var isDashboard = false;
	if((typeof this["load"] == "function")&&((typeof this["Packages"] == "function")||(typeof this["Packages"] == "object"))){
		isRhino = true;
	}else if(typeof this["load"] == "function"){
		isSpidermonkey  = true;
	}else if(window.widget){
		isDashboard = true;
	}

	var tmps = [];
	if((this["djConfig"])&&((djConfig["isDebug"])||(djConfig["debugAtAllCosts"]))){
		tmps.push("debug.js");
	}

	if((this["djConfig"])&&(djConfig["debugAtAllCosts"])&&(!isRhino)&&(!isDashboard)){
		tmps.push("browser_debug.js");
	}

	//Support compatibility packages. Right now this only allows setting one
	//compatibility package. Might need to revisit later down the line to support
	//more than one.
	if((this["djConfig"])&&(djConfig["compat"])){
		tmps.push("compat/" + djConfig["compat"] + ".js");
	}

	var loaderRoot = djConfig["baseScriptUri"];
	if((this["djConfig"])&&(djConfig["baseLoaderUri"])){
		loaderRoot = djConfig["baseLoaderUri"];
	}

	for(var x=0; x < tmps.length; x++){
		var spath = loaderRoot+"src/"+tmps[x];
		if(isRhino||isSpidermonkey){
			load(spath);
		} else {
			try {
				document.write("<scr"+"ipt type='text/javascript' src='"+spath+"'></scr"+"ipt>");
			} catch (e) {
				var script = document.createElement("script");
				script.src = spath;
				document.getElementsByTagName("head")[0].appendChild(script);
			}
		}
	}
})();

// Localization routines

/**
 * The locale to look for string bundles if none are defined for your locale.  Translations for all strings
 * should be provided in this locale.
 */
//TODO: this really belongs in translation metadata, not in code
dojo.fallback_locale = 'en';

/**
 * Returns canonical form of locale, as used by Dojo.  All variants are case-insensitive and are separated by '-'
 * as specified in RFC 3066
 */
dojo.normalizeLocale = function(locale) {
	return locale ? locale.toLowerCase() : dojo.locale;
};

/**
 * requireLocalization() is for loading translated bundles provided within a package in the namespace.
 * Contents are typically strings, but may be any name/value pair, represented in JSON format.
 * A bundle is structured in a program as follows:
 *
 * <package>/
 *  nls/
 *   de/
 *    mybundle.js
 *   de-at/
 *    mybundle.js
 *   en/
 *    mybundle.js
 *   en-us/
 *    mybundle.js
 *   en-gb/
 *    mybundle.js
 *   es/
 *    mybundle.js
 *  ...etc
 *
 * where package is part of the namespace as used by dojo.require().  Each directory is named for a
 * locale as specified by RFC 3066, (http://www.ietf.org/rfc/rfc3066.txt), normalized in lowercase.
 *
 * For a given locale, string bundles will be loaded for that locale and all general locales above it, as well
 * as a system-specified fallback.  For example, "de_at" will also load "de" and "en".  Lookups will traverse
 * the locales in this order.  A build step can preload the bundles to avoid data redundancy and extra network hits.
 *
 * @param modulename package in which the bundle is found
 * @param bundlename bundle name, typically the filename without the '.js' suffix
 * @param locale the locale to load (optional)  By default, the browser's user locale as defined
 *	in dojo.locale
 */
dojo.requireLocalization = function(modulename, bundlename, locale /*optional*/){

	dojo.debug("EXPERIMENTAL: dojo.requireLocalization"); //dojo.experimental

	var syms = dojo.hostenv.getModuleSymbols(modulename);
	var modpath = syms.concat("nls").join("/");

	locale = dojo.normalizeLocale(locale);

	var elements = locale.split('-');
	var searchlist = [];
	for(var i = elements.length; i > 0; i--){
		searchlist.push(elements.slice(0, i).join('-'));
	}
	if(searchlist[searchlist.length-1] != dojo.fallback_locale){
		searchlist.push(dojo.fallback_locale);
	}

	var bundlepackage = [modulename, "_nls", bundlename].join(".");
	var bundle = dojo.hostenv.startPackage(bundlepackage);
	dojo.hostenv.loaded_modules_[bundlepackage] = bundle;
	
	var inherit = false;
	for(var i = searchlist.length - 1; i >= 0; i--){
		var loc = searchlist[i];
		var pkg = [bundlepackage, loc].join(".");
		var loaded = false;
		if(!dojo.hostenv.findModule(pkg)){
			// Mark loaded whether it's found or not, so that further load attempts will not be made
			dojo.hostenv.loaded_modules_[pkg] = null;

			var filespec = [modpath, loc, bundlename].join("/") + '.js';
			loaded = dojo.hostenv.loadPath(filespec, null, function(hash) {
 				bundle[loc] = hash;
 				if(inherit){
					// Use mixins approach to copy string references from inherit bundle, but skip overrides.
					for(var x in inherit){
						if(!bundle[loc][x]){
							bundle[loc][x] = inherit[x];
						}
					}
 				}
/*
				// Use prototype to point to other bundle, then copy in result from loadPath
				bundle[loc] = new function(){};
				if(inherit){ bundle[loc].prototype = inherit; }
				for(var i in hash){ bundle[loc][i] = hash[i]; }
*/
			});
		}else{
			loaded = true;
		}
		if(loaded && bundle[loc]){
			inherit = bundle[loc];
		}
	}
};
