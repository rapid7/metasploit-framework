/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.TaskBar");
dojo.provide("dojo.widget.TaskBarItem");
dojo.require("dojo.widget.Widget");

dojo.widget.TaskBar = function(){
	dojo.widget.Widget.call(this);

	this.widgetType = "TaskBar";
	this.isContainer = true;
}
dojo.inherits(dojo.widget.TaskBar, dojo.widget.Widget);
dojo.widget.tags.addParseTreeHandler("dojo:taskbar");

dojo.widget.TaskBarItem = function(){
	dojo.widget.Widget.call(this);

	this.widgetType = "TaskBarItem";
}
dojo.inherits(dojo.widget.TaskBarItem, dojo.widget.Widget);
dojo.widget.tags.addParseTreeHandler("dojo:taskbaritem");

dojo.requireAfterIf("html", "dojo.widget.html.TaskBar");
