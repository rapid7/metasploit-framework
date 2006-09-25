/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.kwCompoundRequire({
	common: ["dojo.event", "dojo.event.topic"],
	browser: ["dojo.event.browser"],
	dashboard: ["dojo.event.browser"]
});
dojo.provide("dojo.event.*");
