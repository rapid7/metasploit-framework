/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.ShowAction");

dojo.require("dojo.widget.*");
dojo.require("dojo.lang.common");

dojo.widget.ShowAction = function(){}
dojo.lang.extend(dojo.widget.ShowAction, {
	on: "",
	action: "",
	duration: 0,
	from: "",
	to: "",
	auto: "false"
});

dojo.requireAfterIf("html", "dojo.widget.html.ShowAction");