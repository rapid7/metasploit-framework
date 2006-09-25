/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.data.Attribute");
dojo.require("dojo.data.Item");
dojo.require("dojo.lang.assert");

// -------------------------------------------------------------------
// Constructor
// -------------------------------------------------------------------
dojo.data.Attribute = function(/* dojo.data.provider.Base */ dataProvider, /* string */ attributeId) {
	/**
	 * summary:
	 * An Attribute object represents something like a column in 
	 * a relational database.
	 */
	dojo.lang.assertType(dataProvider, [dojo.data.provider.Base, "optional"]);
	dojo.lang.assertType(attributeId, String);
	dojo.data.Item.call(this, dataProvider);
	this._attributeId = attributeId;
};
dojo.inherits(dojo.data.Attribute, dojo.data.Item);

// -------------------------------------------------------------------
// Public instance methods
// -------------------------------------------------------------------
dojo.data.Attribute.prototype.toString = function() {
	return this._attributeId; // string
};

dojo.data.Attribute.prototype.getAttributeId = function() {
	/**
	 * summary: 
	 * Returns the string token that uniquely identifies this
	 * attribute within the context of a data provider.
	 * For a data provider that accesses relational databases,
	 * typical attributeIds might be tokens like "name", "age", 
	 * "ssn", or "dept_key".
	 */ 
	return this._attributeId; // string
};

dojo.data.Attribute.prototype.getType = function() {
	/**
	 * summary: Returns the data type of the values of this attribute.
	 */ 
	return this.get('type'); // dojo.data.Type or null
};

dojo.data.Attribute.prototype.setType = function(/* dojo.data.Type or null */ type) {
	/**
	 * summary: Sets the data type for this attribute.
	 */ 
	this.set('type', type);
};
