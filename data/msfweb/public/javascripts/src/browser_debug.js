/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.hostenv.loadedUris.push("../src/bootstrap1.js");
dojo.hostenv.loadedUris.push("../src/loader.js");
dojo.hostenv.loadedUris.push("../src/hostenv_browser.js");
dojo.hostenv.loadedUris.push("../src/bootstrap2.js");

function removeComments(contents){
	contents = new String((!contents) ? "" : contents);
	// clobber all comments
	contents = contents.replace( /^(.*?)\/\/(.*)$/mg , "$1");
	contents = contents.replace( /(\n)/mg , "__DOJONEWLINE");
	contents = contents.replace( /\/\*(.*?)\*\//g , "");
	return contents.replace( /__DOJONEWLINE/mg , "\n");
}

dojo.hostenv.getRequiresAndProvides = function(contents){
	// FIXME: should probably memoize this!
	if(!contents){ return []; }
	

	// check to see if we need to load anything else first. Ugg.
	var deps = [];
	var tmp;
	RegExp.lastIndex = 0;
	var testExp = /dojo.(hostenv.loadModule|hosetnv.require|require|requireIf|kwCompoundRequire|hostenv.conditionalLoadModule|hostenv.startPackage|provide)\([\w\W]*?\)/mg;
	while((tmp = testExp.exec(contents)) != null){
		deps.push(tmp[0]);
	}
	return deps;
}

dojo.hostenv.getDelayRequiresAndProvides = function(contents){
	// FIXME: should probably memoize this!
	if(!contents){ return []; }

	// check to see if we need to load anything else first. Ugg.
	var deps = [];
	var tmp;
	RegExp.lastIndex = 0;
	var testExp = /dojo.(requireAfterIf)\([\w\W]*?\)/mg;
	while((tmp = testExp.exec(contents)) != null){
		deps.push(tmp[0]);
	}
	return deps;
}

/*
dojo.getNonExistantDescendants = function(objpath){
	var ret = [];
	// fast path for no periods
	if(typeof objpath != "string"){ return dj_global; }
	if(objpath.indexOf('.') == -1){
		if(dj_undef(objpath, dj_global)){
			ret.push[objpath];
		}
		return ret;
	}

	var syms = objpath.split(/\./);
	var obj = dj_global;
	for(var i=0;i<syms.length;++i){
		if(dj_undef(syms[i], obj)){
			for(var j=i; j<syms.length; j++){
				ret.push(syms.slice(0, j+1).join("."));
			}
			break;
		}
	}
	return ret;
}
*/

dojo.clobberLastObject = function(objpath){
	if(objpath.indexOf('.') == -1){
		if(!dj_undef(objpath, dj_global)){
			delete dj_global[objpath];
		}
		return true;
	}

	var syms = objpath.split(/\./);
	var base = dojo.evalObjPath(syms.slice(0, -1).join("."), false);
	var child = syms[syms.length-1];
	if(!dj_undef(child, base)){
		// alert(objpath);
		delete base[child];
		return true;
	}
	return false;
}

var removals = [];

function zip(arr){
	var ret = [];
	var seen = {};
	for(var x=0; x<arr.length; x++){
		if(!seen[arr[x]]){
			ret.push(arr[x]);
			seen[arr[x]] = true;
		}
	}
	return ret;
}

// over-write dj_eval to prevent actual loading of subsequent files
var old_dj_eval = dj_eval;
dj_eval = function(){ return true; }
dojo.hostenv.oldLoadUri = dojo.hostenv.loadUri;
dojo.hostenv.loadUri = function(uri){
	if(dojo.hostenv.loadedUris[uri]){
		return true; // fixes endless recursion opera trac 471
	}
	try{
		var text = this.getText(uri, null, true);
		var requires = dojo.hostenv.getRequiresAndProvides(text);
		eval(requires.join(";"));
		dojo.hostenv.loadedUris.push(uri);
		dojo.hostenv.loadedUris[uri] = true;
		var delayRequires = dojo.hostenv.getDelayRequiresAndProvides(text);
		eval(delayRequires.join(";"));
	}catch(e){ 
		alert(e);
	}
	return true;
}

dojo.hostenv.writeIncludes = function(){
	for(var x=removals.length-1; x>=0; x--){
		dojo.clobberLastObject(removals[x]);
	}
	var depList = [];
	var seen = {};
	for(var x=0; x<dojo.hostenv.loadedUris.length; x++){
		var curi = dojo.hostenv.loadedUris[x];
		// dojo.debug(curi);
		if(!seen[curi]){
			seen[curi] = true;
			depList.push(curi);
		}
	}

	dojo.hostenv._global_omit_module_check = true;
	for(var x=4; x<depList.length; x++){
		document.write("<script type='text/javascript' src='"+depList[x]+"'></script>");
	}
	document.write("<script type='text/javascript'>dojo.hostenv._global_omit_module_check = false;</script>");

	// turn off debugAtAllCosts, so that dojo.require() calls inside of ContentPane hrefs
	// work correctly
	dj_eval = old_dj_eval;
	dojo.hostenv.loadUri = dojo.hostenv.oldLoadUri;
}
