/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.DropdownButton");

dojo.deprecated("dojo.widget.DropdownButton",  "use dojo.widget.ComboButton", "0.4");

// Draws a button with a down arrow;
// when you press the down arrow something appears (usually a menu)

dojo.require("dojo.widget.*");

dojo.widget.tags.addParseTreeHandler("dojo:dropdownbutton");

dojo.widget.DropdownButton = function(){
	dojo.widget.Widget.call(this);

	this.widgetType = "DropdownButton";
}
dojo.inherits(dojo.widget.DropdownButton, dojo.widget.Widget);

dojo.requireAfterIf("html", "dojo.widget.html.DropdownButton");
