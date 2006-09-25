/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/*
 * JScript .NET jsc
 *
 */

dojo.hostenv.name_ = 'jsc';

// Sanity check this is the right hostenv.
// See the Rotor source code jscript/engine/globalobject.cs for what globals
// are available.
if((typeof ScriptEngineMajorVersion != 'function')||(ScriptEngineMajorVersion() < 7)){
	dojo.raise("attempt to use JScript .NET host environment with inappropriate ScriptEngine"); 
}

// for more than you wanted to know about why this import is required even if
// we fully qualify all symbols, see
// http://groups.google.com/groups?th=f050c7aeefdcbde2&rnum=12
import System;

dojo.hostenv.getText = function(uri){
	if(!System.IO.File.Exists(uri)){
		// dojo.raise("No such file '" + uri + "'");
		return 0;
	}
	var reader = new System.IO.StreamReader(uri);
	var contents : String = reader.ReadToEnd();
	return contents;
}

dojo.hostenv.loadUri = function(uri){
	var contents = this.getText(uri);
	if(!contents){
		dojo.raise("got no back contents from uri '" + uri + "': " + contents);
	}
	// TODO: in JScript .NET, eval will not affect the symbol table of the current code?
	var value = dj_eval(contents);
	dojo.debug("jsc eval of contents returned: ", value);
	return 1;

	// for an example doing runtime code compilation, see:
	// http://groups.google.com/groups?selm=eQ1aeciCBHA.1644%40tkmsftngp05&rnum=6
	// Microsoft.JScript or System.CodeDom.Compiler ?
	// var engine = new Microsoft.JScript.Vsa.VsaEngine()
	// what about loading a js file vs. a dll?
	// GetObject("script:" . uri);
}

/* The System.Environment object is useful:
    print ("CommandLine='" + System.Environment.CommandLine + "' " +
	   "program name='" + System.Environment.GetCommandLineArgs()[0] + "' " +
	   "CurrentDirectory='" + System.Environment.CurrentDirectory + "' " +
	   "StackTrace='" + System.Environment.StackTrace + "'");
*/

// same as System.Console.WriteLine
// sigh; Rotor treats symbol "print" at parse time without actually putting it
// in the builtin symbol table.
// Note that the print symbol is not available if jsc is run with the "/print-"
// option.
dojo.hostenv.println = function(s){
	print(s); // = print
}

dojo.hostenv.getLibraryScriptUri = function(){
	return System.Environment.GetCommandLineArgs()[0];
}
