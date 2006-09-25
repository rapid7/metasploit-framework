/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/*
 * SpiderMonkey host environment
 */

dojo.hostenv.name_ = 'spidermonkey';

dojo.hostenv.println = print;
dojo.hostenv.exit = function(exitcode){ 
	quit(exitcode); 
}

// version() returns 0, sigh. and build() returns nothing but just prints.
dojo.hostenv.getVersion = function(){ return version(); }

// make jsc shut up (so we can use jsc for sanity checking) 
/*@cc_on
@if (@_jscript_version >= 7)
var line2pc; var print; var load; var quit;
@end
@*/

if(typeof line2pc == 'undefined'){
	dojo.raise("attempt to use SpiderMonkey host environment when no 'line2pc' global");
}

/*
 * This is a hack that determines the current script file by parsing a generated
 * stack trace (relying on the non-standard "stack" member variable of the
 * SpiderMonkey Error object).
 * If param depth is passed in, it'll return the script file which is that far down
 * the stack, but that does require that you know how deep your stack is when you are
 * calling.
 */
function dj_spidermonkey_current_file(depth){
    var s = '';
    try{
		throw Error("whatever");
	}catch(e){
		s = e.stack;
	}
    // lines are like: bu_getCurrentScriptURI_spidermonkey("ScriptLoader.js")@burst/Runtime.js:101
    var matches = s.match(/[^@]*\.js/gi);
    if(!matches){ 
		dojo.raise("could not parse stack string: '" + s + "'");
	}
    var fname = (typeof depth != 'undefined' && depth) ? matches[depth + 1] : matches[matches.length - 1];
    if(!fname){ 
		dojo.raise("could not find file name in stack string '" + s + "'");
	}
    //print("SpiderMonkeyRuntime got fname '" + fname + "' from stack string '" + s + "'");
    return fname;
}

// call this now because later we may not be on the top of the stack
if(!dojo.hostenv.library_script_uri_){ 
	dojo.hostenv.library_script_uri_ = dj_spidermonkey_current_file(0); 
}

dojo.hostenv.loadUri = function(uri){
	// spidermonkey load() evaluates the contents into the global scope (which
	// is what we want).
	// TODO: sigh, load() does not return a useful value. 
	// Perhaps it is returning the value of the last thing evaluated?
	var ok = load(uri);
	// dojo.debug("spidermonkey load(", uri, ") returned ", ok);
	return 1;
}


