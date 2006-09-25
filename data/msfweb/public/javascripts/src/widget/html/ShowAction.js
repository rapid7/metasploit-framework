/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.ShowAction");

dojo.require("dojo.widget.ShowAction");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.lang.common");

dojo.widget.defineWidget(
	"dojo.widget.html.ShowAction",
	dojo.widget.HtmlWidget,
	null,
	"html",
	function(){
		dojo.widget.ShowAction.call(this);
	}
);
dojo.lang.extend(dojo.widget.html.ShowAction, dojo.widget.ShowAction.prototype);
dojo.lang.extend(dojo.widget.html.ShowAction, {
});