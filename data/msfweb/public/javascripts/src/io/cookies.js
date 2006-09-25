/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.deprecated("dojo.io.cookies", "replaced by dojo.io.cookie", "0.4");
dojo.require("dojo.io.cookie");
if(!dojo.io.cookies) { dojo.io.cookies = dojo.io.cookie; }
dojo.provide("dojo.io.cookies");
