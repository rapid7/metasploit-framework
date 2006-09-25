/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.data.Type");
dojo.require("dojo.data.Item");

// -------------------------------------------------------------------
// Constructor
// -------------------------------------------------------------------
dojo.data.Type = function(/* dojo.data.provider.Base */ dataProvider) {
	/**
	 * summary:
	 * A Type represents a type of value, like Text, Number, Picture,
	 * or Varchar.
	 */
	dojo.data.Item.call(this, dataProvider);
};
dojo.inherits(dojo.data.Type, dojo.data.Item);
