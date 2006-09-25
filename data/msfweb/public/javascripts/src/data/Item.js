/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.data.Item");
dojo.require("dojo.data.Observable");
dojo.require("dojo.data.Value");
dojo.require("dojo.lang.common");
dojo.require("dojo.lang.assert");

// -------------------------------------------------------------------
// Constructor
// -------------------------------------------------------------------
dojo.data.Item = function(/* dojo.data.provider.Base */ dataProvider) {
	/**
	 * summary:
	 * An Item has attributes and attribute values, sort of like 
	 * a record in a database, or a 'struct' in C.  Instances of
	 * the Item class know how to store and retrieve their
	 * attribute values.
	 */
	dojo.lang.assertType(dataProvider, [dojo.data.provider.Base, "optional"]);
	dojo.data.Observable.call(this);
	this._dataProvider = dataProvider;
	this._dictionaryOfAttributeValues = {};
};
dojo.inherits(dojo.data.Item, dojo.data.Observable);

// -------------------------------------------------------------------
// Public class methods
// -------------------------------------------------------------------
dojo.data.Item.compare = function(/* dojo.data.Item */ itemOne, /* dojo.data.Item */ itemTwo) {
	/**
	 * summary:
	 * Given two Items to compare, this method returns 0, 1, or -1.
	 * This method is designed to be used by sorting routines, like
	 * the JavaScript built-in Array sort() method.
	 * 
	 * Example:
	 * <pre>
	 *   var a = dataProvider.newItem("kermit");
	 *   var b = dataProvider.newItem("elmo");
	 *   var c = dataProvider.newItem("grover");
	 *   var array = new Array(a, b, c);
	 *   array.sort(dojo.data.Item.compare);
	 * </pre>
	 */
	dojo.lang.assertType(itemOne, dojo.data.Item);
	if (!dojo.lang.isOfType(itemTwo, dojo.data.Item)) {
		return -1;
	}
	var nameOne = itemOne.getName();
	var nameTwo = itemTwo.getName();
	if (nameOne == nameTwo) {
		var attributeArrayOne = itemOne.getAttributes();
		var attributeArrayTwo = itemTwo.getAttributes();
		if (attributeArrayOne.length != attributeArrayTwo.length) {
			if (attributeArrayOne.length > attributeArrayTwo.length) {
				return 1; 
			} else {
				return -1;
			}
		}
		for (var i in attributeArrayOne) {
			var attribute = attributeArrayOne[i];
			var arrayOfValuesOne = itemOne.getValues(attribute);
			var arrayOfValuesTwo = itemTwo.getValues(attribute);
			dojo.lang.assert(arrayOfValuesOne && (arrayOfValuesOne.length > 0));
			if (!arrayOfValuesTwo) {
				return 1;
			}
			if (arrayOfValuesOne.length != arrayOfValuesTwo.length) {
				if (arrayOfValuesOne.length > arrayOfValuesTwo.length) {
					return 1; 
				} else {
					return -1;
				}
			}
			for (var j in arrayOfValuesOne) {
				var value = arrayOfValuesOne[j];
				if (!itemTwo.hasAttributeValue(value)) {
					return 1;
				}
			}
			return 0;
		}
	} else {
		if (nameOne > nameTwo) {
			return 1; 
		} else {
			return -1;  // 0, 1, or -1
		}
	}
};

// -------------------------------------------------------------------
// Public instance methods
// -------------------------------------------------------------------
dojo.data.Item.prototype.toString = function() {
	/**
	 * Returns a simple string representation of the item.
	 */
	var arrayOfStrings = [];
	var attributes = this.getAttributes();
	for (var i in attributes) {
		var attribute = attributes[i];
		var arrayOfValues = this.getValues(attribute);
		var valueString;
		if (arrayOfValues.length == 1) {
			valueString = arrayOfValues[0];
		} else {
			valueString = '[';
			valueString += arrayOfValues.join(', ');
			valueString += ']';
		}
		arrayOfStrings.push('  ' + attribute + ': ' + valueString);
	}
	var returnString = '{ ';
	returnString += arrayOfStrings.join(',\n');
	returnString += ' }';
	return returnString; // string
};

dojo.data.Item.prototype.compare = function(/* dojo.data.Item */ otherItem) {
	/**
	 * summary: Compares this Item to another Item, and returns 0, 1, or -1.
	 */ 
	return dojo.data.Item.compare(this, otherItem); // 0, 1, or -1
};

dojo.data.Item.prototype.isEqual = function(/* dojo.data.Item */ otherItem) {
	/**
	 * summary: Returns true if this Item is equal to the otherItem, or false otherwise.
	 */
	return (this.compare(otherItem) == 0); // boolean
};

dojo.data.Item.prototype.getName = function() {
	return this.get('name');
};

dojo.data.Item.prototype.get = function(/* string or dojo.data.Attribute */ attributeId) {
	/**
	 * summary: Returns a single literal value, like "foo" or 33.
	 */ 
	// dojo.lang.assertType(attributeId, [String, dojo.data.Attribute]);
	var literalOrValueOrArray = this._dictionaryOfAttributeValues[attributeId];
	if (dojo.lang.isUndefined(literalOrValueOrArray)) {
		return null; // null
	}
	if (literalOrValueOrArray instanceof dojo.data.Value) {
		return literalOrValueOrArray.getValue(); // literal
	}
	if (dojo.lang.isArray(literalOrValueOrArray)) {
		var dojoDataValue = literalOrValueOrArray[0];
		return dojoDataValue.getValue(); // literal
	}
	return literalOrValueOrArray; // literal
};

dojo.data.Item.prototype.getValue = function(/* string or dojo.data.Attribute */ attributeId) {
	/**
	 * summary: Returns a single instance of dojo.data.Value.
	 */ 
	// dojo.lang.assertType(attributeId, [String, dojo.data.Attribute]);
	var literalOrValueOrArray = this._dictionaryOfAttributeValues[attributeId];
	if (dojo.lang.isUndefined(literalOrValueOrArray)) {
		return null; // null
	}
	if (literalOrValueOrArray instanceof dojo.data.Value) {
		return literalOrValueOrArray; // dojo.data.Value
	}
	if (dojo.lang.isArray(literalOrValueOrArray)) {
		var dojoDataValue = literalOrValueOrArray[0];
		return dojoDataValue; // dojo.data.Value
	}
	var literal = literalOrValueOrArray;
	dojoDataValue = new dojo.data.Value(literal);
	this._dictionaryOfAttributeValues[attributeId] = dojoDataValue;
	return dojoDataValue; // dojo.data.Value
};

dojo.data.Item.prototype.getValues = function(/* string or dojo.data.Attribute */ attributeId) {
	/**
	 * summary: Returns an array of dojo.data.Value objects.
	 */ 
	// dojo.lang.assertType(attributeId, [String, dojo.data.Attribute]);
	var literalOrValueOrArray = this._dictionaryOfAttributeValues[attributeId];
	if (dojo.lang.isUndefined(literalOrValueOrArray)) {
		return null; // null
	}
	if (literalOrValueOrArray instanceof dojo.data.Value) {
		var array = [literalOrValueOrArray];
		this._dictionaryOfAttributeValues[attributeId] = array;
		return array; // Array
	}
	if (dojo.lang.isArray(literalOrValueOrArray)) {
		return literalOrValueOrArray; // Array
	}
	var literal = literalOrValueOrArray;
	var dojoDataValue = new dojo.data.Value(literal);
	array = [dojoDataValue];
	this._dictionaryOfAttributeValues[attributeId] = array;
	return array; // Array
};

dojo.data.Item.prototype.load = function(/* string or dojo.data.Attribute */ attributeId, /* anything */ value) {
	/**
	 * summary: 
	 * Used for loading an attribute value into an item when
	 * the item is first being loaded into memory from some
	 * data store (such as a file).
	 */ 
	// dojo.lang.assertType(attributeId, [String, dojo.data.Attribute]);
	this._dataProvider.registerAttribute(attributeId);
	var literalOrValueOrArray = this._dictionaryOfAttributeValues[attributeId];
	if (dojo.lang.isUndefined(literalOrValueOrArray)) {
		this._dictionaryOfAttributeValues[attributeId] = value;
		return;
	}
	if (!(value instanceof dojo.data.Value)) {
		value = new dojo.data.Value(value);
	}
	if (literalOrValueOrArray instanceof dojo.data.Value) {
		var array = [literalOrValueOrArray, value];
		this._dictionaryOfAttributeValues[attributeId] = array;
		return;
	}
	if (dojo.lang.isArray(literalOrValueOrArray)) {
		literalOrValueOrArray.push(value);
		return;
	}
	var literal = literalOrValueOrArray;
	var dojoDataValue = new dojo.data.Value(literal);
	array = [dojoDataValue, value];
	this._dictionaryOfAttributeValues[attributeId] = array;
};

dojo.data.Item.prototype.set = function(/* string or dojo.data.Attribute */ attributeId, /* anything */ value) {
	/**
	 * summary: 
	 * Used for setting an attribute value as a result of a
	 * user action.
	 */ 
	// dojo.lang.assertType(attributeId, [String, dojo.data.Attribute]);
	this._dataProvider.registerAttribute(attributeId);
	this._dictionaryOfAttributeValues[attributeId] = value;
	this._dataProvider.noteChange(this, attributeId, value);
};

dojo.data.Item.prototype.setValue = function(/* string or dojo.data.Attribute */ attributeId, /* dojo.data.Value */ value) {
	this.set(attributeId, value);
};

dojo.data.Item.prototype.addValue = function(/* string or dojo.data.Attribute */ attributeId, /* anything */ value) {
	/**
	 * summary: 
	 * Used for adding an attribute value as a result of a
	 * user action.
	 */ 
	this.load(attributeId, value);
	this._dataProvider.noteChange(this, attributeId, value);
};

dojo.data.Item.prototype.setValues = function(/* string or dojo.data.Attribute */ attributeId, /* Array */ arrayOfValues) {
	/**
	 * summary: 
	 * Used for setting an array of attribute values as a result of a
	 * user action.
	 */
	// dojo.lang.assertType(attributeId, [String, dojo.data.Attribute]);
	dojo.lang.assertType(arrayOfValues, Array);
	this._dataProvider.registerAttribute(attributeId);
	var finalArray = [];
	this._dictionaryOfAttributeValues[attributeId] = finalArray;
	for (var i in arrayOfValues) {
		var value = arrayOfValues[i];
		if (!(value instanceof dojo.data.Value)) {
			value = new dojo.data.Value(value);
		}
		finalArray.push(value);
		this._dataProvider.noteChange(this, attributeId, value);
	}
};

dojo.data.Item.prototype.getAttributes = function() {
	/**
	 * summary: 
	 * Returns an array containing all of the attributes for which
	 * this item has attribute values.
	 */ 
	var arrayOfAttributes = [];
	for (var key in this._dictionaryOfAttributeValues) {
		arrayOfAttributes.push(this._dataProvider.getAttribute(key));
	}
	return arrayOfAttributes; // Array
};

dojo.data.Item.prototype.hasAttribute = function(/* string or dojo.data.Attribute */ attributeId) {
	/**
	 * summary: Returns true if the given attribute of the item has been assigned any value.
	 */ 
	// dojo.lang.assertType(attributeId, [String, dojo.data.Attribute]);
	for (var key in this._dictionaryOfAttributeValues) {
		if (key == attributeId) {
			return true; // boolean
		}
	}
	return false; // boolean
};

dojo.data.Item.prototype.hasAttributeValue = function(/* string or dojo.data.Attribute */ attributeId, /* anything */ value) {
	/**
	 * summary: Returns true if the given attribute of the item has been assigned the given value.
	 */ 
	var arrayOfValues = this.getValues(attributeId);
	for (var i in arrayOfValues) {
		var candidateValue = arrayOfValues[i];
		if (candidateValue.isEqual(value)) {
			return true; // boolean
		}
	}
	return false; // boolean
};


