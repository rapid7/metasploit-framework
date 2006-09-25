/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.kwCompoundRequire({
	browser: [
		"dojo.widget.demoEngine.DemoItem",
		"dojo.widget.demoEngine.DemoNavigator",
		"dojo.widget.demoEngine.DemoPane",
		"dojo.widget.demoEngine.SourcePane",
		"dojo.widget.demoEngine.DemoContainer"
	]
});
dojo.provide("dojo.widget.demoEngine.*");
