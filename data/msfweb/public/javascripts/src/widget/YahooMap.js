/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.YahooMap");
dojo.provide("dojo.widget.YahooMap.Controls");
dojo.require("dojo.widget.*");

dojo.widget.defineWidget(
	"dojo.widget.YahooMap",
	dojo.widget.Widget,
	{ isContainer: false }
);

dojo.widget.YahooMap.Controls={
	MapType:"maptype",
	Pan:"pan",
	ZoomLong:"zoomlong",
	ZoomShort:"zoomshort"
};
dojo.requireAfterIf("html", "dojo.widget.html.YahooMap");
