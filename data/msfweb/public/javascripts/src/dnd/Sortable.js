/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.dnd.Sortable");
dojo.require("dojo.dnd.*");

dojo.dnd.Sortable = function () {}

dojo.lang.extend(dojo.dnd.Sortable, {

	ondragstart: function (e) {
		var dragObject = e.target;
		while (dragObject.parentNode && dragObject.parentNode != this) {
			dragObject = dragObject.parentNode;
		}
		// TODO: should apply HtmlDropTarget interface to self
		// TODO: should apply HtmlDragObject interface?
		return dragObject;
	}

});
