/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.debug.Firebug");

if (console.log) {
	dojo.hostenv.println=console.log;
} else {
	dojo.debug("dojo.debug.Firebug requires Firebug > 0.4");
}
