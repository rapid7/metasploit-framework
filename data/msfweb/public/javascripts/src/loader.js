/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/*
 * loader.js - runs before the hostenv_*.js file. Contains all of the package loading methods.
 */

//A semi-colon is at the start of the line because after doing a build, this function definition
//get compressed onto the same line as the last line in bootstrap1.js. That list line is just a
//curly bracket, and the browser complains about that syntax. The semicolon fixes it. Putting it
//here instead of at the end of bootstrap1.js, since it is more of an issue for this file, (using
//the closure), and bootstrap1.js could change in the future.
;(function(){
	//Additional properties for dojo.hostenv
	var _addHostEnv = {
		pkgFileName: "__package__",
	
		// for recursion protection
		loading_modules_: {},
		loaded_modules_: {},
		addedToLoadingCount: [],
		removedFromLoadingCount: [],
	
		inFlightCount: 0,
	
		// FIXME: it should be possible to pull module prefixes in from djConfig
		modulePrefixes_: {
			dojo: {name: "dojo", value: "src"}
		},
	
	
		setModulePrefix: function(module, prefix){
			this.modulePrefixes_[module] = {name: module, value: prefix};
		},
	
		getModulePrefix: function(module){
			var mp = this.modulePrefixes_;
			if((mp[module])&&(mp[module]["name"])){
				return mp[module].value;
			}
			return module;
		},

		getTextStack: [],
		loadUriStack: [],
		loadedUris: [],
	
		//WARNING: This variable is referenced by packages outside of bootstrap: FloatingPane.js and undo/browser.js
		post_load_: false,
		
		//Egad! Lots of test files push on this directly instead of using dojo.addOnLoad.
		modulesLoadedListeners: [],
		unloadListeners: [],
		loadNotifying: false
	};
	
	//Add all of these properties to dojo.hostenv
	for(var param in _addHostEnv){
		dojo.hostenv[param] = _addHostEnv[param];
	}
})();

/**
 * Loads and interprets the script located at relpath, which is relative to the
 * script root directory.  If the script is found but its interpretation causes
 * a runtime exception, that exception is not caught by us, so the caller will
 * see it.  We return a true value if and only if the script is found.
 *
 * For now, we do not have an implementation of a true search path.  We
 * consider only the single base script uri, as returned by getBaseScriptUri().
 *
 * @param relpath A relative path to a script (no leading '/', and typically
 * ending in '.js').
 * @param module A module whose existance to check for after loading a path.
 * Can be used to determine success or failure of the load.
 * @param cb a function to pass the result of evaluating the script (optional)
 */
dojo.hostenv.loadPath = function(relpath, module /*optional*/, cb /*optional*/){
	var uri;
	if((relpath.charAt(0) == '/')||(relpath.match(/^\w+:/))){
		// dojo.raise("relpath '" + relpath + "'; must be relative");
		uri = relpath;
	}else{
		uri = this.getBaseScriptUri() + relpath;
	}
	if(djConfig.cacheBust && dojo.render.html.capable){
		uri += "?" + String(djConfig.cacheBust).replace(/\W+/g,"");
	}
	try{
		return ((!module) ? this.loadUri(uri, cb) : this.loadUriAndCheck(uri, module, cb));
	}catch(e){
		dojo.debug(e);
		return false;
	}
}

/**
 * Reads the contents of the URI, and evaluates the contents.
 * Returns true if it succeeded. Returns false if the URI reading failed.
 * Throws if the evaluation throws.
 * The result of the eval is not available to the caller TODO: now it is; was this a deliberate restriction?
 *
 * @param uri a uri which points at the script to be loaded
 * @param cb a function to process the result of evaluating the script as an expression (optional)
 */
dojo.hostenv.loadUri = function(uri, cb /*optional*/){
	if(this.loadedUris[uri]){
		return 1;
	}
	var contents = this.getText(uri, null, true);
	if(contents == null){ return 0; }
	this.loadedUris[uri] = true;
	if(cb){ contents = '('+contents+')'; }
	var value = dj_eval(contents);
	if(cb){
		cb(value);
	}
	return 1;
}

// FIXME: probably need to add logging to this method
dojo.hostenv.loadUriAndCheck = function(uri, module, cb){
	var ok = true;
	try{
		ok = this.loadUri(uri, cb);
	}catch(e){
		dojo.debug("failed loading ", uri, " with error: ", e);
	}
	return ((ok)&&(this.findModule(module, false))) ? true : false;
}

dojo.loaded = function(){ }
dojo.unloaded = function(){ }

dojo.hostenv.loaded = function(){
	this.loadNotifying = true;
	this.post_load_ = true;
	var mll = this.modulesLoadedListeners;
	for(var x=0; x<mll.length; x++){
		mll[x]();
	}

	//Clear listeners so new ones can be added
	//For other xdomain package loads after the initial load.
	this.modulesLoadedListeners = [];
	this.loadNotifying = false;

	dojo.loaded();
}

dojo.hostenv.unloaded = function(){
	var mll = this.unloadListeners;
	while(mll.length){
		(mll.pop())();
	}
	dojo.unloaded();
}

/*
Call styles:
	dojo.addOnLoad(functionPointer)
	dojo.addOnLoad(object, "functionName")
*/
dojo.addOnLoad = function(obj, fcnName) {
	var dh = dojo.hostenv;
	if(arguments.length == 1) {
		dh.modulesLoadedListeners.push(obj);
	} else if(arguments.length > 1) {
		dh.modulesLoadedListeners.push(function() {
			obj[fcnName]();
		});
	}

	//Added for xdomain loading. dojo.addOnLoad is used to
	//indicate callbacks after doing some dojo.require() statements.
	//In the xdomain case, if all the requires are loaded (after initial
	//page load), then immediately call any listeners.
	if(dh.post_load_ && dh.inFlightCount == 0 && !dh.loadNotifying){
		dh.callLoaded();
	}
}

dojo.addOnUnload = function(obj, fcnName){
	var dh = dojo.hostenv;
	if(arguments.length == 1){
		dh.unloadListeners.push(obj);
	} else if(arguments.length > 1) {
		dh.unloadListeners.push(function() {
			obj[fcnName]();
		});
	}
}

dojo.hostenv.modulesLoaded = function(){
	if(this.post_load_){ return; }
	if((this.loadUriStack.length==0)&&(this.getTextStack.length==0)){
		if(this.inFlightCount > 0){ 
			dojo.debug("files still in flight!");
			return;
		}
		dojo.hostenv.callLoaded();
	}
}

dojo.hostenv.callLoaded = function(){
	if(typeof setTimeout == "object"){
		setTimeout("dojo.hostenv.loaded();", 0);
	}else{
		dojo.hostenv.loaded();
	}
}

dojo.hostenv.getModuleSymbols = function(modulename) {
	var syms = modulename.split(".");
	for(var i = syms.length - 1; i > 0; i--){
		var parentModule = syms.slice(0, i).join(".");
		var parentModulePath = this.getModulePrefix(parentModule);
		if(parentModulePath != parentModule){
			syms.splice(0, i, parentModulePath);
			break;
		}
	}
	return syms;
}

/**
* loadModule("A.B") first checks to see if symbol A.B is defined. 
* If it is, it is simply returned (nothing to do).
*
* If it is not defined, it will look for "A/B.js" in the script root directory,
* followed by "A.js".
*
* It throws if it cannot find a file to load, or if the symbol A.B is not
* defined after loading.
*
* It returns the object A.B.
*
* This does nothing about importing symbols into the current package.
* It is presumed that the caller will take care of that. For example, to import
* all symbols:
*
*    with (dojo.hostenv.loadModule("A.B")) {
*       ...
*    }
*
* And to import just the leaf symbol:
*
*    var B = dojo.hostenv.loadModule("A.B");
*    ...
*
* dj_load is an alias for dojo.hostenv.loadModule
*/
dojo.hostenv._global_omit_module_check = false;
dojo.hostenv.loadModule = function(modulename, exact_only, omit_module_check){
	if(!modulename){ return; }
	omit_module_check = this._global_omit_module_check || omit_module_check;
	var module = this.findModule(modulename, false);
	if(module){
		return module;
	}

	// protect against infinite recursion from mutual dependencies
	if(dj_undef(modulename, this.loading_modules_)){
		this.addedToLoadingCount.push(modulename);
	}
	this.loading_modules_[modulename] = 1;

	// convert periods to slashes
	var relpath = modulename.replace(/\./g, '/') + '.js';

	var syms = this.getModuleSymbols(modulename);
	var startedRelative = ((syms[0].charAt(0) != '/')&&(!syms[0].match(/^\w+:/)));
	var last = syms[syms.length - 1];
	// figure out if we're looking for a full package, if so, we want to do
	// things slightly diffrently
	var nsyms = modulename.split(".");
	if(last=="*"){
		modulename = (nsyms.slice(0, -1)).join('.');

		while(syms.length){
			syms.pop();
			syms.push(this.pkgFileName);
			relpath = syms.join("/") + '.js';
			if(startedRelative && (relpath.charAt(0)=="/")){
				relpath = relpath.slice(1);
			}
			ok = this.loadPath(relpath, ((!omit_module_check) ? modulename : null));
			if(ok){ break; }
			syms.pop();
		}
	}else{
		relpath = syms.join("/") + '.js';
		modulename = nsyms.join('.');
		var ok = this.loadPath(relpath, ((!omit_module_check) ? modulename : null));
		if((!ok)&&(!exact_only)){
			syms.pop();
			while(syms.length){
				relpath = syms.join('/') + '.js';
				ok = this.loadPath(relpath, ((!omit_module_check) ? modulename : null));
				if(ok){ break; }
				syms.pop();
				relpath = syms.join('/') + '/'+this.pkgFileName+'.js';
				if(startedRelative && (relpath.charAt(0)=="/")){
					relpath = relpath.slice(1);
				}
				ok = this.loadPath(relpath, ((!omit_module_check) ? modulename : null));
				if(ok){ break; }
			}
		}

		if((!ok)&&(!omit_module_check)){
			dojo.raise("Could not load '" + modulename + "'; last tried '" + relpath + "'");
		}
	}

	// check that the symbol was defined
	//Don't bother if we're doing xdomain (asynchronous) loading.
	if(!omit_module_check && !this["isXDomain"]){
		// pass in false so we can give better error
		module = this.findModule(modulename, false);
		if(!module){
			dojo.raise("symbol '" + modulename + "' is not defined after loading '" + relpath + "'"); 
		}
	}

	return module;
}

/**
* startPackage("A.B") follows the path, and at each level creates a new empty
* object or uses what already exists. It returns the result.
*/
dojo.hostenv.startPackage = function(packname){
	var modref = dojo.evalObjPath((packname.split(".").slice(0, -1)).join('.'));
	this.loaded_modules_[(new String(packname)).toLowerCase()] = modref;

	var syms = packname.split(/\./);
	if(syms[syms.length-1]=="*"){
		syms.pop();
	}
	return dojo.evalObjPath(syms.join("."), true);
}

/**
 * findModule("A.B") returns the object A.B if it exists, otherwise null.
 * @param modulename A string like 'A.B'.
 * @param must_exist Optional, defualt false. throw instead of returning null
 * if the module does not currently exist.
 */
dojo.hostenv.findModule = function(modulename, must_exist){
	// check cache
	/*
	if(!dj_undef(modulename, this.modules_)){
		return this.modules_[modulename];
	}
	*/

	var lmn = (new String(modulename)).toLowerCase();

	if(this.loaded_modules_[lmn]){
		return this.loaded_modules_[lmn];
	}

	// see if symbol is defined anyway
	var module = dojo.evalObjPath(modulename);
	if((modulename)&&(typeof module != 'undefined')&&(module)){
		this.loaded_modules_[lmn] = module;
		return module;
	}

	if(must_exist){
		dojo.raise("no loaded module named '" + modulename + "'");
	}
	return null;
}

//Start of old bootstrap2:

/*
 * This method taks a "map" of arrays which one can use to optionally load dojo
 * modules. The map is indexed by the possible dojo.hostenv.name_ values, with
 * two additional values: "default" and "common". The items in the "default"
 * array will be loaded if none of the other items have been choosen based on
 * the hostenv.name_ item. The items in the "common" array will _always_ be
 * loaded, regardless of which list is chosen.  Here's how it's normally
 * called:
 *
 *	dojo.kwCompoundRequire({
 *		browser: [
 *			["foo.bar.baz", true, true], // an example that passes multiple args to loadModule()
 *			"foo.sample.*",
 *			"foo.test,
 *		],
 *		default: [ "foo.sample.*" ],
 *		common: [ "really.important.module.*" ]
 *	});
 */
dojo.kwCompoundRequire = function(modMap){
	var common = modMap["common"]||[];
	var result = (modMap[dojo.hostenv.name_]) ? common.concat(modMap[dojo.hostenv.name_]||[]) : common.concat(modMap["default"]||[]);

	for(var x=0; x<result.length; x++){
		var curr = result[x];
		if(curr.constructor == Array){
			dojo.hostenv.loadModule.apply(dojo.hostenv, curr);
		}else{
			dojo.hostenv.loadModule(curr);
		}
	}
}

dojo.require = function(){
	dojo.hostenv.loadModule.apply(dojo.hostenv, arguments);
}

dojo.requireIf = function(){
	if((arguments[0] === true)||(arguments[0]=="common")||(arguments[0] && dojo.render[arguments[0]].capable)){
		var args = [];
		for (var i = 1; i < arguments.length; i++) { args.push(arguments[i]); }
		dojo.require.apply(dojo, args);
	}
}

dojo.requireAfterIf = dojo.requireIf;

dojo.provide = function(){
	return dojo.hostenv.startPackage.apply(dojo.hostenv, arguments);
}

dojo.setModulePrefix = function(module, prefix){
	return dojo.hostenv.setModulePrefix(module, prefix);
}

// determine if an object supports a given method
// useful for longer api chains where you have to test each object in the chain
dojo.exists = function(obj, name){
	var p = name.split(".");
	for(var i = 0; i < p.length; i++){
	if(!(obj[p[i]])) return false;
		obj = obj[p[i]];
	}
	return true;
}
