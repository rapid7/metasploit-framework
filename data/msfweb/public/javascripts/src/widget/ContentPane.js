/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

// This widget doesn't do anything; is basically the same as <div>.
// It's useful as a child of LayoutContainer, SplitContainer, or TabContainer.
// But note that those classes can contain any widget as a child.

dojo.provide("dojo.widget.ContentPane");
dojo.requireAfterIf("html", "dojo.widget.html.ContentPane");
