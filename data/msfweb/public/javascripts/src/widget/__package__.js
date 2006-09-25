/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.kwCompoundRequire({
	common: ["dojo.xml.Parse", 
			 "dojo.widget.Widget", 
			 "dojo.widget.Parse", 
			 "dojo.widget.Manager"],
	browser: ["dojo.widget.DomWidget",
			  "dojo.widget.HtmlWidget"],
	dashboard: ["dojo.widget.DomWidget",
			  "dojo.widget.HtmlWidget"],
	svg: 	 ["dojo.widget.SvgWidget"],
	rhino: 	 ["dojo.widget.SwtWidget"]
});
dojo.provide("dojo.widget.*");
