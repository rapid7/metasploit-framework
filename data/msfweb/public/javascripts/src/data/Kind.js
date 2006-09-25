/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.data.Kind");
dojo.require("dojo.data.Item");

// -------------------------------------------------------------------
// Constructor
// -------------------------------------------------------------------
dojo.data.Kind = function(/* dojo.data.provider.Base */ dataProvider) {
	/**
	 * summary:
	 * A Kind represents a kind of item.  In the dojo data model
	 * the item Snoopy might belong to the 'kind' Dog, where in
	 * a Java program the object Snoopy would belong to the 'class'
	 * Dog, and in MySQL the record for Snoopy would be in the 
	 * table Dog.
	 */
	dojo.data.Item.call(this, dataProvider);
};
dojo.inherits(dojo.data.Kind, dojo.data.Item);
