/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/*
 * Adobe SVG Viewer host environment
 */
if(typeof window == 'undefined'){
	dojo.raise("attempt to use adobe svg hostenv when no window object");
}

with(dojo.render){
	name = navigator.appName;
	ver = parseFloat(navigator.appVersion, 10);
	switch(navigator.platform){
		case "MacOS":
			os.osx =  true;
			break;
		case "Linux":
			os.linux =  true;
			break;
		case "Windows":
			os.win =  true;
			break;
		default:
			os.linux = true;
			break;
	};
	svg.capable = true;
	svg.support.builtin = true;
	svg.adobe = true;
};

// browserEval("alert(window.location);");

dojo.hostenv.println = function(s){
	try{
    // FIXME: this may not work with adobe's viewer, as we may first need a 
		// reference to the svgDocument
		// FIXME: need a way to determine where to position the text for this
    var ti = document.createElement("text");
    ti.setAttribute("x","50");
		var yPos = 25 + 15*document.getElementsByTagName("text").length;
    ti.setAttribute("y",yPos);
		var tn = document.createTextNode(s);
		ti.appendChild(tn);
		document.documentElement.appendChild(ti);
	}catch(e){

	}
}

dojo.debug = function() {
	if (!djConfig.isDebug) { return; }
	var args = arguments;
	if(typeof dojo.hostenv.println != 'function'){
		dojo.raise("attempt to call dojo.debug when there is no dojo.hostenv println implementation (yet?)");
	}
	var isJUM = dj_global["jum"];
	var s = isJUM ? "": "DEBUG: ";
	for(var i=0;i<args.length;++i){ s += args[i]; }
	if(isJUM){ // this seems to be the only way to get JUM to "play nice"
		jum.debug(s);
	}else{
		dojo.hostenv.println(s);
	}
}

dojo.hostenv.startPackage("dojo.hostenv");

dojo.hostenv.name_ = 'adobesvg';

dojo.hostenv.anonCtr = 0;
dojo.hostenv.anon = {};

dojo.hostenv.nameAnonFunc = function(anonFuncPtr, namespaceObj){
	var ret = "_"+this.anonCtr++;
	var nso = (namespaceObj || this.anon);
	while(typeof nso[ret] != "undefined"){
		ret = "_"+this.anonCtr++;
	}
	nso[ret] = anonFuncPtr;
	return ret;
}

dojo.hostenv.modulesLoadedFired = false;
dojo.hostenv.modulesLoadedListeners = [];
dojo.hostenv.getTextStack = [];
dojo.hostenv.loadUriStack = [];
dojo.hostenv.loadedUris = [];


dojo.hostenv.modulesLoaded = function(){
	if(this.modulesLoadedFired){ return; }
	if((this.loadUriStack.length==0)&&(this.getTextStack.length==0)){
		if(this.inFlightCount > 0){ 
			dojo.debug("couldn't initialize, there are files still in flight");
			return;
		}
		this.modulesLoadedFired = true;
		var mll = this.modulesLoadedListeners;
		for(var x=0; x<mll.length; x++){
			mll[x]();
		}
	}
}

dojo.hostenv.getNewAnonFunc = function(){
	var ret = "_"+this.anonCtr++;
	while(typeof this.anon[ret] != "undefined"){
		ret = "_"+this.anonCtr++;
	}
	// this.anon[ret] = function(){};
	eval("dojo.nostenv.anon."+ret+" = function(){};");
	return [ret, this.anon[ret]];
}

dojo.hostenv.displayStack = function(){
	var oa = [];
	var stack = this.loadUriStack;
	for(var x=0; x<stack.length; x++){
		oa.unshift([stack[x][0], (typeof stack[x][2])]);
	}
	dojo.debug("<pre>"+oa.join("\n")+"</pre>");
}

dojo.hostenv.unwindUriStack = function(){
	var stack = this.loadUriStack;
	for(var x in dojo.hostenv.loadedUris){
		for(var y=stack.length-1; y>=0; y--){
			if(stack[y][0]==x){
				stack.splice(y, 1);
			}
		}
	}
	var next = stack.pop();
	if((!next)&&(stack.length==0)){ 
		return;
	}
	for(var x=0; x<stack.length; x++){
		if((stack[x][0]==next[0])&&(stack[x][2])){
			next[2] == stack[x][2]
		}
	}
	var last = next;
	while(dojo.hostenv.loadedUris[next[0]]){
		last = next;
		next = stack.pop();
	}
	while(typeof next[2] == "string"){ // unwind as far as we can
		try{
			// dojo.debug("<pre><![CDATA["+next[2]+"]]></pre>");
			dj_eval(next[2]);
			next[1](true);
		}catch(e){
			dojo.debug("we got an error when loading "+next[0]);
			dojo.debug("error: "+e);
			// for(var x in e){ alert(x+" "+e[x]); }
		}
		dojo.hostenv.loadedUris[next[0]] = true;
		dojo.hostenv.loadedUris.push(next[0]);
		last = next;
		next = stack.pop();
		if((!next)&&(stack.length==0)){ break; }
		while(dojo.hostenv.loadedUris[next[0]]){
			last = next;
			next = stack.pop();
		}
	}
	if(next){
		stack.push(next);
		dojo.debug("### CHOKED ON: "+next[0]);
	}
}

/**
 * Reads the contents of the URI, and evaluates the contents.
 * Returns true if it succeeded. Returns false if the URI reading failed. Throws if the evaluation throws.
 * The result of the eval is not available to the caller.
 */
dojo.hostenv.loadUri = function(uri, cb){
	if(dojo.hostenv.loadedUris[uri]){
		return;
	}
	var stack = this.loadUriStack;
	stack.push([uri, cb, null]);
	var tcb = function(contents){
		// gratuitous hack for Adobe SVG 3, what a fucking POS
		if(contents.content){
			contents = contents.content;
		}

		// stack management
		var next = stack.pop();
		if((!next)&&(stack.length==0)){ 
			dojo.hostenv.modulesLoaded();
			return;
		}
		if(typeof contents == "string"){
			stack.push(next);
			for(var x=0; x<stack.length; x++){
				if(stack[x][0]==uri){
					stack[x][2] = contents;
				}
			}
			next = stack.pop();
		}
		if(dojo.hostenv.loadedUris[next[0]]){ 
			// dojo.debug("WE ALREADY HAD: "+next[0]);
			dojo.hostenv.unwindUriStack();
			return;
		}
		// push back onto stack
		stack.push(next);
		if(next[0]!=uri){
			//  and then unwind as far as we can
			if(typeof next[2] == "string"){
				dojo.hostenv.unwindUriStack();
			}

		}else{
			if(!contents){ 
				next[1](false);
			}else{
				var deps = dojo.hostenv.getDepsForEval(next[2]);
				if(deps.length>0){
					eval(deps.join(";"));
				}else{
					dojo.hostenv.unwindUriStack();
				}
			}
		}
	}
	this.getText(uri, tcb, true);
}

/**
 * Reads the contents of the URI, and evaluates the contents.
 * Returns true if it succeeded. Returns false if the URI reading failed. Throws if the evaluation throws.
 * The result of the eval is not available to the caller.
 */
dojo.hostenv.loadUri = function(uri, cb){
	if(dojo.hostenv.loadedUris[uri]){
		return;
	}
	var stack = this.loadUriStack;
	stack.push([uri, cb, null]);
	var tcb = function(contents){
		// gratuitous hack for Adobe SVG 3, what a fucking POS
		if(contents.content){
			contents = contents.content;
		}

		// stack management
		var next = stack.pop();
		if((!next)&&(stack.length==0)){ 
			dojo.hostenv.modulesLoaded();
			return;
		}
		if(typeof contents == "string"){
			stack.push(next);
			for(var x=0; x<stack.length; x++){
				if(stack[x][0]==uri){
					stack[x][2] = contents;
				}
			}
			next = stack.pop();
		}
		if(dojo.hostenv.loadedUris[next[0]]){ 
			// dojo.debug("WE ALREADY HAD: "+next[0]);
			dojo.hostenv.unwindUriStack();
			return;
		}
		// push back onto stack
		stack.push(next);
		if(next[0]!=uri){
			//  and then unwind as far as we can
			if(typeof next[2] == "string"){
				dojo.hostenv.unwindUriStack();
			}

		}else{
			if(!contents){ 
				next[1](false);
			}else{
				var deps = dojo.hostenv.getDepsForEval(next[2]);
				if(deps.length>0){
					eval(deps.join(";"));
				}else{
					dojo.hostenv.unwindUriStack();
				}
			}
		}
	}
	this.getText(uri, tcb, true);
}

/**
* loadModule("A.B") first checks to see if symbol A.B is defined. 
* If it is, it is simply returned (nothing to do).
* If it is not defined, it will look for "A/B.js" in the script root directory, followed
* by "A.js".
* It throws if it cannot find a file to load, or if the symbol A.B is not defined after loading.
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
dojo.hostenv.loadModule = function(modulename, exact_only, omit_module_check){
	// alert("dojo.hostenv.loadModule('"+modulename+"');");
	var module = this.findModule(modulename, 0);
	if(module){
		return module;
	}

	// dojo.debug("dojo.hostenv.loadModule('"+modulename+"');");

	// protect against infinite recursion from mutual dependencies
	if (typeof this.loading_modules_[modulename] !== 'undefined'){
		// NOTE: this should never throw an exception!! "recursive" includes
		// are normal in the course of app and module building, so blow out of
		// it gracefully, but log it in debug mode

		// dojo.raise("recursive attempt to load module '" + modulename + "'");
		dojo.debug("recursive attempt to load module '" + modulename + "'");
	}else{
		this.addedToLoadingCount.push(modulename);
	}
	this.loading_modules_[modulename] = 1;


	// convert periods to slashes
	var relpath = modulename.replace(/\./g, '/') + '.js';

	var syms = modulename.split(".");
	var nsyms = modulename.split(".");
	if(syms[0]=="dojo"){ // FIXME: need a smarter way to do this!
		syms[0] = "src"; 
	}
	var last = syms.pop();
	syms.push(last);
	// figure out if we're looking for a full package, if so, we want to do
	// things slightly diffrently
	var _this = this;
	var pfn = this.pkgFileName;
	if(last=="*"){
		modulename = (nsyms.slice(0, -1)).join('.');

		var module = this.findModule(modulename, 0);
		// dojo.debug("found: "+modulename+"="+module);
		if(module){
			_this.removedFromLoadingCount.push(modulename);
			return module;
		}

		var nextTry = function(lastStatus){
			if(lastStatus){ 
				module = _this.findModule(modulename, false); // pass in false so we can give better error
				if((!module)&&(syms[syms.length-1]!=pfn)){
					dojo.raise("Module symbol '" + modulename + "' is not defined after loading '" + relpath + "'"); 
				}
				if(module){
					_this.removedFromLoadingCount.push(modulename);
					dojo.hostenv.modulesLoaded();
					return;
				}
			}
			syms.pop();
			syms.push(pfn);
			// dojo.debug("syms: "+syms);
			relpath = syms.join("/") + '.js';
			if(relpath.charAt(0)=="/"){
				relpath = relpath.slice(1);
			}
			// dojo.debug("relpath: "+relpath);
			_this.loadPath(relpath, ((!omit_module_check) ? modulename : null), nextTry);
		}

		nextTry();
	}else{
		relpath = syms.join("/") + '.js';
		modulename = nsyms.join('.');

		var nextTry = function(lastStatus){
			// dojo.debug("lastStatus: "+lastStatus);
			if(lastStatus){ 
				// dojo.debug("inital relpath: "+relpath);
				module = _this.findModule(modulename, false); // pass in false so we can give better error
				// if(!module){
				if((!module)&&(syms[syms.length-1]!=pfn)){
					dojo.raise("Module symbol '" + modulename + "' is not defined after loading '" + relpath + "'"); 
				}
				if(module){
					_this.removedFromLoadingCount.push(modulename);
					dojo.hostenv.modulesLoaded();
					return;
				}
			}
			var setPKG = (syms[syms.length-1]==pfn) ? false : true;
			syms.pop();
			if(setPKG){
				syms.push(pfn);
			}
			relpath = syms.join("/") + '.js';
			if(relpath.charAt(0)=="/"){
				relpath = relpath.slice(1);
			}
			// dojo.debug("relpath: "+relpath);
			_this.loadPath(relpath, ((!omit_module_check) ? modulename : null), nextTry);
		}

		this.loadPath(relpath, ((!omit_module_check) ? modulename : null), nextTry);
	}
	return;
}

/**
 * Read the contents of the specified uri and return those contents.
 *
 * FIXME: Make sure this is consistent with other implementations of getText
 * @param uri A relative or absolute uri. If absolute, it still must be in the same "domain" as we are.
 * @param async_cb If not specified, returns false as synchronous is not
 * supported. If specified, load asynchronously, and use async_cb as the handler which receives the result of the request.
 * @param fail_ok Default false. If fail_ok and !async_cb and loading fails, return null instead of throwing.
 */ 
dojo.hostenv.async_cb = null;

dojo.hostenv.unWindGetTextStack = function(){
	if(dojo.hostenv.inFlightCount>0){
		setTimeout("dojo.hostenv.unWindGetTextStack()", 100);
		return;
	}
	// we serialize because this goddamned environment is too fucked up
	// to know how to do anything else
	dojo.hostenv.inFlightCount++;
	var next = dojo.hostenv.getTextStack.pop();
	if((!next)&&(dojo.hostenv.getTextStack.length==0)){ 
		dojo.hostenv.inFlightCount--;
		dojo.hostenv.async_cb = function(){};
		return;
	}
	dojo.hostenv.async_cb = next[1];
	// http = window.getURL(uri, dojo.hostenv.anon[cbn]);
	window.getURL(next[0], function(result){ 
		dojo.hostenv.inFlightCount--;
		dojo.hostenv.async_cb(result.content);
		dojo.hostenv.unWindGetTextStack();
	});
}

dojo.hostenv.getText = function(uri, async_cb, fail_ok){
	// dojo.debug("Calling getText()");
	try{
		if(async_cb){
			dojo.hostenv.getTextStack.push([uri, async_cb, fail_ok]);
			dojo.hostenv.unWindGetTextStack();
		}else{
			return dojo.raise("No synchronous XMLHTTP implementation available, for uri " + uri);
		}
	}catch(e){
		return dojo.raise("No XMLHTTP implementation available, for uri " + uri);
	}
}


/**
 * Makes an async post to the specified uri.
 *
 * FIXME: Not sure that we need this, but adding for completeness.
 * More details about the implementation of this are available at 
 * http://wiki.svg.org/index.php/PostUrl
 * @param uri A relative or absolute uri. If absolute, it still must be in the same "domain" as we are.
 * @param async_cb If not specified, returns false as synchronous is not
 * supported. If specified, load asynchronously, and use async_cb as the progress handler which takes the xmlhttp object as its argument. If async_cb, this function returns null.
 * @param text Data to post
 * @param fail_ok Default false. If fail_ok and !async_cb and loading fails, return null instead of throwing.
 * @param mime_type optional MIME type of the posted data (such as "text/plain")
 * @param encoding optional encoding for data. null, 'gzip' and 'deflate' are possible values. If browser does not support binary post this parameter is ignored.
 */ 
dojo.hostenv.postText = function(uri, async_cb, text, fail_ok, mime_type, encoding){
	var http = null;
	
	var async_callback = function(httpResponse){
		if (!httpResponse.success) {
			dojo.raise("Request for uri '" + uri + "' resulted in " + httpResponse.status);
		}
		
		if(!httpResponse.content) {
			if (!fail_ok) dojo.raise("Request for uri '" + uri + "' resulted in no content");
			return null;
		}
		// FIXME: wtf, I'm losing a reference to async_cb
		async_cb(httpResponse.content);
	}
	
	try {
		if(async_cb) {
			http = window.postURL(uri, text, async_callback, mimeType, encoding);
		} else {
		return dojo.raise("No synchronous XMLHTTP post implementation available, for uri " + uri);
		}
	} catch(e) {
		return dojo.raise("No XMLHTTP post implementation available, for uri " + uri);
	}
}

/*
 * It turns out that if we check *right now*, as this script file is being loaded,
 * then the last script element in the window DOM is ourselves.
 * That is because any subsequent script elements haven't shown up in the document
 * object yet.
 */
function dj_last_script_src() {
	var scripts = window.document.getElementsByTagName('script');
	if(scripts.length < 1){ 
		dojo.raise("No script elements in window.document, so can't figure out my script src"); 
	}
	var li = scripts.length-1;
	var xlinkNS = "http://www.w3.org/1999/xlink";
	var src = null;
	var script = null;
	while(!src){
		script = scripts.item(li);
		src = script.getAttributeNS(xlinkNS,"href");
		li--;
		if(li<0){ break; }
		// break;
	}
	if(!src){
		dojo.raise("Last script element (out of " + scripts.length + ") has no src");
	}
	return src;
}

if(!dojo.hostenv["library_script_uri_"]){
	dojo.hostenv.library_script_uri_ = dj_last_script_src();
}

// dojo.hostenv.loadUri = function(uri){
	/* FIXME: adding a script element doesn't seem to be synchronous, and so
	 * checking for namespace or object existance after loadUri using this
	 * method will error out. Need to figure out some other way of handling
	 * this!
	 */
	/*
	var se = document.createElement("script");
	se.src = uri;
	var head = document.getElementsByTagName("head")[0];
	head.appendChild(se);
	// document.write("<script type='text/javascript' src='"+uri+"' />");
	return 1;
}
*/
