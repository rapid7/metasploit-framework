/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.LinkPane");
dojo.provide("dojo.widget.html.LinkPane");

//
// a div that loads from a URL.  (Similar to an iframe, but
// it's in the same environment as the main window)
//

dojo.require("dojo.widget.LinkPane");
dojo.require("dojo.widget.*");
dojo.require("dojo.event.*");
dojo.require("dojo.io.*");
dojo.require("dojo.widget.ContentPane");
dojo.require("dojo.html");
dojo.require("dojo.style");
dojo.require("dojo.dom");
dojo.require("dojo.string");


dojo.widget.html.LinkPane = function(){
	dojo.widget.html.ContentPane.call(this);
}

dojo.inherits(dojo.widget.html.LinkPane, dojo.widget.html.ContentPane);

dojo.lang.extend(dojo.widget.html.LinkPane, {
	widgetType: "LinkPane",

	// I'm using a template because the user may specify the input as
	// <a href="foo.html">label</a>, in which case we need to get rid of the
	// <a> because we don't want a link.
	templateString: '<div class="dojoLinkPane"></div>',

	fillInTemplate: function(args, frag){
		var source = this.getFragNodeRef(frag);

		// If user has specified node contents, they become the label
		// (the link must be plain text)
		this.label += source.innerHTML;

		var source = this.getFragNodeRef(frag);
		dojo.html.copyStyle(this.domNode, source);
	}
});
