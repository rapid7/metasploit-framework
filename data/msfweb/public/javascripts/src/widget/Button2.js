/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.Button2");
dojo.require("dojo.widget.Button");
dojo.require("dojo.widget.*");

dojo.widget.tags.addParseTreeHandler("dojo:button2");
dojo.widget.tags.addParseTreeHandler("dojo:dropdownbutton2");
dojo.widget.tags.addParseTreeHandler("dojo:combobutton2");

dojo.deprecated("dojo.widget.Button2", "Use dojo.widget.Button instead", "0.4");

dojo.requireAfterIf("html", "dojo.widget.html.Button2");

dojo.widget.Button2 = function(){}
dojo.inherits(dojo.widget.Button2, dojo.widget.Button);
dojo.lang.extend(dojo.widget.Button2, { widgetType: "Button2" });

dojo.widget.DropDownButton2 = function(){}
dojo.inherits(dojo.widget.DropDownButton2, dojo.widget.DropDownButton);
dojo.lang.extend(dojo.widget.DropDownButton2, { widgetType: "DropDownButton2" });

dojo.widget.ComboButton2 = function(){}
dojo.inherits(dojo.widget.ComboButton2, dojo.widget.ComboButton);
dojo.lang.extend(dojo.widget.ComboButton2, { widgetType: "ComboButton2" });
