/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.lang.assert");

dojo.require("dojo.lang.common");
dojo.require("dojo.lang.array");
dojo.require("dojo.lang.type");

// -------------------------------------------------------------------
// Assertion methods
// -------------------------------------------------------------------

/**
 * Throws an exception if the assertion fails.
 *
 * If the asserted condition is true, this method does nothing. If the
 * condition is false, we throw an error with a error message.  
 *
 * @param	booleanValue	A boolean value, which needs to be true for the assertion to succeed.
 * @param	message	Optional. A string describing the assertion.
 * @throws	Throws an Error if 'booleanValue' is false.
 */
dojo.lang.assert = function(booleanValue, message){
	if(!booleanValue){
		var errorMessage = "An assert statement failed.\n" +
			"The method dojo.lang.assert() was called with a 'false' value.\n";
		if(message){
			errorMessage += "Here's the assert message:\n" + message + "\n";
		}
		// Use throw instead of dojo.raise, until bug #264 is fixed:
		// dojo.raise(errorMessage);
		throw new Error(errorMessage);
	}
}

/**
 * Given a value and a data type, this method checks the type of the value
 * to make sure it matches the data type, and throws an exception if there
 * is a mismatch.
 *
 * Examples:
 * <pre>
 *   dojo.lang.assertType("foo", String);
 *   dojo.lang.assertType(12345, Number);
 *   dojo.lang.assertType(false, Boolean);
 *   dojo.lang.assertType([6, 8], Array);
 *   dojo.lang.assertType(dojo.lang.assertType, Function);
 *   dojo.lang.assertType({foo: "bar"}, Object);
 *   dojo.lang.assertType(new Date(), Date);
 * </pre>
 *
 * @scope	public function
 * @param	value	Any literal value or object instance.
 * @param	type	A class of object, or a literal type, or the string name of a type, or an array with a list of types.
 * @param	message	Optional. A string describing the assertion.
 * @throws	Throws an Error if 'value' is not of type 'type'.
 */
dojo.lang.assertType = function(value, type, message){
	if(!dojo.lang.isOfType(value, type)){
		if(!message){
			if(!dojo.lang.assertType._errorMessage){
				dojo.lang.assertType._errorMessage = "Type mismatch: dojo.lang.assertType() failed.";
			}
			message = dojo.lang.assertType._errorMessage;
		}
		dojo.lang.assert(false, message);
	}
}

/**
 * Given an anonymous object and a list of expected property names, this
 * method check to make sure the object does not have any properties
 * that aren't on the list of expected properties, and throws an Error
 * if there are unexpected properties. This is useful for doing error
 * checking on keyword arguments, to make sure there aren't typos.
 *
 * Examples:
 * <pre>
 *   dojo.lang.assertValidKeywords({a: 1, b: 2}, ["a", "b"]);
 *   dojo.lang.assertValidKeywords({a: 1, b: 2}, ["a", "b", "c"]);
 *   dojo.lang.assertValidKeywords({foo: "iggy"}, ["foo"]);
 *   dojo.lang.assertValidKeywords({foo: "iggy"}, ["foo", "bar"]);
 *   dojo.lang.assertValidKeywords({foo: "iggy"}, {foo: null, bar: null});
 * </pre>
 *
 * @scope	public function
 * @param	object	An anonymous object.
 * @param	expectedProperties	An array of strings (or an object with all the expected properties).
 * @param	message	Optional. A string describing the assertion.
 * @throws	Throws an Error if 'value' is not of type 'type'.
 */
dojo.lang.assertValidKeywords = function(object, expectedProperties, message){
	var key;
	if(!message){
		if(!dojo.lang.assertValidKeywords._errorMessage){
			dojo.lang.assertValidKeywords._errorMessage = "In dojo.lang.assertValidKeywords(), found invalid keyword:";
		}
		message = dojo.lang.assertValidKeywords._errorMessage;
	}
	if(dojo.lang.isArray(expectedProperties)){
		for(key in object){
			if(!dojo.lang.inArray(expectedProperties, key)){
				dojo.lang.assert(false, message + " " + key);
			}
		}
	}else{
		for(key in object){
			if(!(key in expectedProperties)){
				dojo.lang.assert(false, message + " " + key);
			}
		}
	}
}
