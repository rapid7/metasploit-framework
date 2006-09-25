/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.ContextMenu");

dojo.deprecated("dojo.widget.ContextMenu",  "use dojo.widget.Menu2", "0.4");

dojo.require("dojo.widget.*");
dojo.require("dojo.widget.DomWidget");

dojo.widget.ContextMenu = function(){
	dojo.widget.Widget.call(this);
	this.widgetType = "ContextMenu";
	this.isContainer = true;
	this.isOpened = false;
	
	// copy children widgets output directly to parent (this node), to avoid
	// errors trying to insert an <li> under a <div>
	this.snarfChildDomOutput = true;

}

dojo.inherits(dojo.widget.ContextMenu, dojo.widget.Widget);
dojo.widget.tags.addParseTreeHandler("dojo:contextmenu");

dojo.requireAfterIf("html", "dojo.widget.html.ContextMenu");
