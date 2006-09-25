/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/*
 * WSH
 */

dojo.hostenv.name_ = 'wsh';

// make jsc shut up (so can sanity check)
/*@cc_on
@if (@_jscript_version >= 7)
var WScript;
@end
@*/

// make sure we are in right environment
if(typeof WScript == 'undefined'){
	dojo.raise("attempt to use WSH host environment when no WScript global");
}

dojo.hostenv.println = WScript.Echo;

dojo.hostenv.getCurrentScriptUri = function(){
	return WScript.ScriptFullName();
}

dojo.hostenv.getText = function(fpath){
	var fso = new ActiveXObject("Scripting.FileSystemObject");
	var istream = fso.OpenTextFile(fpath, 1); // iomode==1 means read only
	if(!istream){
		return null;
	}
	var contents = istream.ReadAll();
	istream.Close();
	return contents;
}

dojo.hostenv.exit = function(exitcode){ WScript.Quit(exitcode); }
