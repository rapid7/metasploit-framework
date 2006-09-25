/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.uuid.LightweightGenerator");

/**
 * The LightweightGenerator is intended to be small and fast,
 * but not necessarily good.
 * 
 * Small: The LightweightGenerator has a small footprint. 
 * Once comments are stripped, it's only about 25 lines of 
 * code, and it doesn't dojo.require() any other packages.
 *
 * Fast: The LightweightGenerator can generate lots of new 
 * UUIDs fairly quickly (at least, more quickly than the other 
 * dojo UUID generators).
 *
 * Not necessarily good: We use Math.random() as our source
 * of randomness, which may or may not provide much randomness. 
 */
dojo.uuid.LightweightGenerator = new function() {

	var HEX_RADIX = 16;

// --------------------------------------------------
// Private functions
// --------------------------------------------------
	function _generateRandomEightCharacterHexString() {
		// Make random32bitNumber be a randomly generated floating point number
		// between 0 and (4,294,967,296 - 1), inclusive.
		var random32bitNumber = Math.floor( (Math.random() % 1) * Math.pow(2, 32) );
		var eightCharacterHexString = random32bitNumber.toString(HEX_RADIX);
		while (eightCharacterHexString.length < 8) {
			eightCharacterHexString = "0" + eightCharacterHexString;
		}
		return eightCharacterHexString; // for example: "3B12F1DF"
	}

// --------------------------------------------------
// Public functions
// --------------------------------------------------

/**
 * This function generates random UUIDs, meaning "version 4" UUIDs.
 * For example, a typical generated value would be something like
 * "3b12f1df-5232-4804-897e-917bf397618a".
 *
 * Examples:
 * <pre>
 *   var string = dojo.uuid.LightweightGenerator.generate();
 *   var string = dojo.uuid.LightweightGenerator.generate(String);
 *   var uuid   = dojo.uuid.LightweightGenerator.generate(dojo.uuid.Uuid);
 * </pre>
 *
 * @param	returnType	Optional. The type of instance to return.
 * @return	A newly generated version 4 UUID.
 */
	this.generate = function(returnType) {
		var hyphen = "-";
		var versionCodeForRandomlyGeneratedUuids = "4"; // 8 == binary2hex("0100")
		var variantCodeForDCEUuids = "8"; // 8 == binary2hex("1000")
		var a = _generateRandomEightCharacterHexString();
		var b = _generateRandomEightCharacterHexString();
		b = b.substring(0, 4) + hyphen + versionCodeForRandomlyGeneratedUuids + b.substring(5, 8);
		var c = _generateRandomEightCharacterHexString();
		c = variantCodeForDCEUuids + c.substring(1, 4) + hyphen + c.substring(4, 8);
		var d = _generateRandomEightCharacterHexString();
		var returnValue = a + hyphen + b + hyphen + c + d;
		returnValue = returnValue.toLowerCase();
		if (returnType && (returnType != String)) {
			returnValue = new returnType(returnValue);
		}
		return returnValue;
	};
}();
