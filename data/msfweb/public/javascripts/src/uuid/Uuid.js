/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.uuid.Uuid");
dojo.require("dojo.lang.*");

// -------------------------------------------------------------------
// Constructor
// -------------------------------------------------------------------
/**
 * The Uuid class offers methods for inspecting existing UUIDs.
 *
 * Examples:
 * <pre>
 *   var uuid;
 *   uuid = new dojo.uuid.Uuid("3b12f1df-5232-4804-897e-917bf397618a");
 *   uuid = new dojo.uuid.Uuid(); // "00000000-0000-0000-0000-000000000000"
 *   uuid = new dojo.uuid.Uuid(dojo.uuid.RandomGenerator);
 *   uuid = new dojo.uuid.Uuid(dojo.uuid.TimeBasedGenerator);
 *
 *   dojo.uuid.Uuid.setGenerator(dojo.uuid.RandomGenerator);
 *   uuid = new dojo.uuid.Uuid();
 *   dojo.lang.assert(!uuid.isEqual(dojo.uuid.Uuid.NIL_UUID));
 * </pre>
 *
 * @scope	public instance constructor
 * @param	uuidString	A 36-character string that conforms to the UUID spec.
 * @param	generator	A UUID generator, such as dojo.uuid.TimeBasedGenerator.
 */
dojo.uuid.Uuid = function(input) {
	this._uuidString = dojo.uuid.Uuid.NIL_UUID;
	if (input) {
		if (dojo.lang.isString(input)) {
			this._uuidString = input.toLowerCase();
			dojo.lang.assert(this.isValid());
		} else {
			if (dojo.lang.isObject(input) && input.generate) {
				var generator = input;
				this._uuidString = generator.generate();
				dojo.lang.assert(this.isValid());
			} else {
				// we got passed something other than a string
				dojo.lang.assert(false, "The dojo.uuid.Uuid() constructor must be initializated with a UUID string.");
			}
		}
	} else {
		var ourGenerator = dojo.uuid.Uuid.getGenerator();
		if (ourGenerator) {
			this._uuidString = ourGenerator.generate();
			dojo.lang.assert(this.isValid());
		}
	}
};

// -------------------------------------------------------------------
// Public constants
// -------------------------------------------------------------------
dojo.uuid.Uuid.NIL_UUID = "00000000-0000-0000-0000-000000000000";
dojo.uuid.Uuid.Version = {
	UNKNOWN: 0,
	TIME_BASED: 1,
	DCE_SECURITY: 2,
	NAME_BASED_MD5: 3,
	RANDOM: 4,
	NAME_BASED_SHA1: 5 };
dojo.uuid.Uuid.Variant = {
	NCS: "0",
	DCE: "10",
	MICROSOFT: "110",
	UNKNOWN: "111" };
dojo.uuid.Uuid.HEX_RADIX = 16;

// -------------------------------------------------------------------
// Public class methods
// -------------------------------------------------------------------
/**
 * Given two UUIDs to compare, this method returns 0, 1, or -1.
 * This method is designed to be used by sorting routines, like
 * the JavaScript built-in Array sort() method.
 * This implementation is intended to match the sample 
 * implementation in IETF RFC 4122: 
 * http://www.ietf.org/rfc/rfc4122.txt
 * 
 * Example:
 * <pre>
 *   var generator = dojo.uuid.TimeBasedGenerator;
 *   var a = new dojo.uuid.Uuid(generator);
 *   var b = new dojo.uuid.Uuid(generator);
 *   var c = new dojo.uuid.Uuid(generator);
 *   var array = new Array(a, b, c);
 *   array.sort(dojo.uuid.Uuid.compare);
 * </pre>
 *
 * @param	uuidOne	A dojo.uuid.Uuid instance, or a string representing a UUID.
 * @param	uuidTwo	A dojo.uuid.Uuid instance, or a string representing a UUID.
 * @return   Returns either 0, 1, or -1.
 */
dojo.uuid.Uuid.compare = function(uuidOne, uuidTwo) {
	var uuidStringOne = uuidOne.toString();
	var uuidStringTwo = uuidTwo.toString();
	if (uuidStringOne > uuidStringTwo) return 1;
	if (uuidStringOne < uuidStringTwo) return -1;
	return 0;
};

/**
 * Sets the default generator, which will be used by the 
 * "new dojo.uuid.Uuid()" constructor if no parameters
 * are passed in.
 *
 * @param	generator	A UUID generator, such as dojo.uuid.TimeBasedGenerator.
 * @return   Returns true or false. True if this UUID is equal to the otherUuid.
 */
dojo.uuid.Uuid.setGenerator = function(generator) {
	dojo.lang.assert(!generator || (dojo.lang.isObject(generator) && generator.generate));
	dojo.uuid.Uuid._ourGenerator = generator;
};

/**
 * Returns the default generator.  See setGenerator().
 *
 * @return   A UUID generator, such as dojo.uuid.TimeBasedGenerator.
 */
dojo.uuid.Uuid.getGenerator = function(generator) {
	return dojo.uuid.Uuid._ourGenerator;
};

// -------------------------------------------------------------------
// Public instance methods
// -------------------------------------------------------------------
/**
 * Returns a 36-character string representing the UUID, such 
 * as "3b12f1df-5232-4804-897e-917bf397618a".
 * 
 * Examples:
 * <pre>
 *   var uuid = new dojo.uuid.Uuid(dojo.uuid.TimeBasedGenerator);
 *   var s;
 *   s = uuid.toString();       //  eb529fec-6498-11d7-b236-000629ba5445
 *   s = uuid.toString('{}');   // {eb529fec-6498-11d7-b236-000629ba5445}
 *   s = uuid.toString('()');   // (eb529fec-6498-11d7-b236-000629ba5445)
 *   s = uuid.toString('""');   // "eb529fec-6498-11d7-b236-000629ba5445"
 *   s = uuid.toString("''");   // 'eb529fec-6498-11d7-b236-000629ba5445'
 *   s = uuid.toString('!-');   //  eb529fec649811d7b236000629ba5445
 *   s = uuid.toString('urn');  //  urn:uuid:eb529fec-6498-11d7-b236-000629ba5445
 * </pre>
 *
 * @param	uuidOne	A dojo.uuid.Uuid instance, or a string representing a UUID.
 * @return   Returns a standard 36-character UUID string, or something similar. 
 */
dojo.uuid.Uuid.prototype.toString = function(format) {
	if (format) {
		switch (format) {
			case '{}':
				return '{' + this._uuidString + '}';
				break;
			case '()':
				return '(' + this._uuidString + ')';
				break;
			case '""':
				return '"' + this._uuidString + '"';
				break;
			case "''":
				return "'" + this._uuidString + "'";
				break;
			case 'urn':
				return 'urn:uuid:' + this._uuidString;
				break;
			case '!-':
				return this._uuidString.split('-').join('');
				break;
			default:
				// we got passed something other than what we expected
				dojo.lang.assert(false, "The toString() method of dojo.uuid.Uuid was passed a bogus format.");
		}
	} else {
		return this._uuidString;
	}
};

/**
 * Compares this UUID to another UUID, and returns 0, 1, or -1.
 * This implementation is intended to match the sample 
 * implementation in IETF RFC 4122: 
 * http://www.ietf.org/rfc/rfc4122.txt
 *
 * @param	otherUuid	A dojo.uuid.Uuid instance, or a string representing a UUID.
 * @return   Returns either 0, 1, or -1.
 */
dojo.uuid.Uuid.prototype.compare = function(otherUuid) {
	return dojo.uuid.Uuid.compare(this, otherUuid);
};

/**
 * Returns true if this UUID is equal to the otherUuid, or
 * false otherwise.
 *
 * @param	otherUuid	A dojo.uuid.Uuid instance, or a string representing a UUID.
 * @return   Returns true or false. True if this UUID is equal to the otherUuid.
 */
dojo.uuid.Uuid.prototype.isEqual = function(otherUuid) {
	return (this.compare(otherUuid) == 0);
};

/**
 * Returns true if the UUID was initialized with a valid value.
 *
 * @return   True if the UUID is valid, or false if it is not.
 */
dojo.uuid.Uuid.prototype.isValid = function() {
	try {
		dojo.lang.assertType(this._uuidString, String);
		dojo.lang.assert(this._uuidString.length == 36);
		dojo.lang.assert(this._uuidString == this._uuidString.toLowerCase());
		var arrayOfParts = this._uuidString.split("-");
		dojo.lang.assert(arrayOfParts.length == 5);
		dojo.lang.assert(arrayOfParts[0].length == 8);
		dojo.lang.assert(arrayOfParts[1].length == 4);
		dojo.lang.assert(arrayOfParts[2].length == 4);
		dojo.lang.assert(arrayOfParts[3].length == 4);
		dojo.lang.assert(arrayOfParts[4].length == 12);
		for (var i in arrayOfParts) {
			var part = arrayOfParts[i];
			var integer = parseInt(part, dojo.uuid.Uuid.HEX_RADIX);
			dojo.lang.assert(isFinite(integer));
		}
		return true;
	} catch (e) {
		return false;
	}
};

/**
 * Returns a variant code that indicates what type of UUID this is.
 * For example:
 * <pre>
 *   var uuid = new dojo.uuid.Uuid("3b12f1df-5232-4804-897e-917bf397618a");
 *   var variant = uuid.getVariant();
 *   dojo.lang.assert(variant == dojo.uuid.Uuid.Variant.DCE);
 * </pre>
 *
 * @return   Returns one of the enumarted dojo.uuid.Uuid.Variant values.
 */
dojo.uuid.Uuid.prototype.getVariant = function() {
	// "3b12f1df-5232-4804-897e-917bf397618a"
	//                     ^
	//                     |
	//         (variant "10__" == DCE)
	var variantCharacter = this._uuidString.charAt(19);
	var variantNumber = parseInt(variantCharacter, dojo.uuid.Uuid.HEX_RADIX);
	dojo.lang.assert((variantNumber >= 0) && (variantNumber <= 16));

	if (!dojo.uuid.Uuid._ourVariantLookupTable) {
		var Variant = dojo.uuid.Uuid.Variant;
		var lookupTable = [];

		lookupTable[0x0] = Variant.NCS;       // 0000
		lookupTable[0x1] = Variant.NCS;       // 0001
		lookupTable[0x2] = Variant.NCS;       // 0010
		lookupTable[0x3] = Variant.NCS;       // 0011

		lookupTable[0x4] = Variant.NCS;       // 0100
		lookupTable[0x5] = Variant.NCS;       // 0101
		lookupTable[0x6] = Variant.NCS;       // 0110
		lookupTable[0x7] = Variant.NCS;       // 0111

		lookupTable[0x8] = Variant.DCE;       // 1000
		lookupTable[0x9] = Variant.DCE;       // 1001
		lookupTable[0xA] = Variant.DCE;       // 1010
		lookupTable[0xB] = Variant.DCE;       // 1011

		lookupTable[0xC] = Variant.MICROSOFT; // 1100
		lookupTable[0xD] = Variant.MICROSOFT; // 1101
		lookupTable[0xE] = Variant.UNKNOWN;   // 1110
		lookupTable[0xF] = Variant.UNKNOWN;   // 1111
		
		dojo.uuid.Uuid._ourVariantLookupTable = lookupTable;
	}

	return dojo.uuid.Uuid._ourVariantLookupTable[variantNumber];
};

/**
 * Returns a version number that indicates what type of UUID this is.
 * For example:
 * <pre>
 *   var uuid = new dojo.uuid.Uuid("b4308fb0-86cd-11da-a72b-0800200c9a66");
 *   var version = uuid.getVersion();
 *   dojo.lang.assert(version == dojo.uuid.Uuid.Version.TIME_BASED);
 * </pre>
 *
 * @return   Returns one of the enumerated dojo.uuid.Uuid.Version values.
 * @throws   Throws an Error if this is not a DCE Variant UUID.
 */
dojo.uuid.Uuid.prototype.getVersion = function() {
	if (!this._versionNumber) {
		var errorMessage = "Called getVersion() on a dojo.uuid.Uuid that was not a DCE Variant UUID.";
		dojo.lang.assert(this.getVariant() == dojo.uuid.Uuid.Variant.DCE, errorMessage);
	
		// "b4308fb0-86cd-11da-a72b-0800200c9a66"
		//                ^
		//                |
		//       (version 1 == TIME_BASED)
		var versionCharacter = this._uuidString.charAt(14);
		this._versionNumber = parseInt(versionCharacter, dojo.uuid.Uuid.HEX_RADIX);
	}
	return this._versionNumber;
};

/**
 * If this is a version 1 UUID (a time-based UUID), this method returns a 
 * 12-character string with the "node" or "pseudonode" portion of the UUID, 
 * which is the rightmost 12 characters.  
 * Throws an Error if this is not a version 1 UUID.
 *
 * @return   Returns a 12-character string, which will look something like "917bf397618a".
 * @throws   Throws an Error if this is not a version 1 UUID.
 */
dojo.uuid.Uuid.prototype.getNode = function() {
	if (!this._nodeString) {
		var errorMessage = "Called getNode() on a dojo.uuid.Uuid that was not a TIME_BASED UUID.";
		dojo.lang.assert(this.getVersion() == dojo.uuid.Uuid.Version.TIME_BASED, errorMessage);

		var arrayOfStrings = this._uuidString.split('-');
		this._nodeString = arrayOfStrings[4];
	}
	return this._nodeString;
};

/**
 * If this is a version 1 UUID (a time-based UUID), this method returns 
 * the timestamp value encoded in the UUID.  The caller can ask for the
 * timestamp to be returned either as a JavaScript Date object or as a 
 * 15-character string of hex digits.
 * Throws an Error if this is not a version 1 UUID.
 *
 * Examples:
 * <pre>
 *   var uuid = new dojo.uuid.Uuid("b4308fb0-86cd-11da-a72b-0800200c9a66");
 *   var date, string, hexString;
 *   date   = uuid.getTimestamp();         // returns a JavaScript Date
 *   date   = uuid.getTimestamp(Date);     // 
 *   string = uuid.getTimestamp(String);   // "Mon, 16 Jan 2006 20:21:41 GMT"
 *   hexString = uuid.getTimestamp("hex"); // "1da86cdb4308fb0"
 * </pre>
 *
 * @return   Returns the timestamp value as a JavaScript Date object or a 15-character string of hex digits.
 * @throws   Throws an Error if this is not a version 1 UUID.
 */
dojo.uuid.Uuid.prototype.getTimestamp = function(returnType) {
	var errorMessage = "Called getTimestamp() on a dojo.uuid.Uuid that was not a TIME_BASED UUID.";
	dojo.lang.assert(this.getVersion() == dojo.uuid.Uuid.Version.TIME_BASED, errorMessage);
	
	if (!returnType) {returnType = null};
	switch (returnType) {
		case "string":
		case String:
			return this.getTimestamp(Date).toUTCString();
			break;
		case "hex":
			// Return a 15-character string of hex digits containing the 
			// timestamp for this UUID, with the high-order bits first.
			if (!this._timestampAsHexString) {
				var arrayOfStrings = this._uuidString.split('-');
				var hexTimeLow = arrayOfStrings[0];
				var hexTimeMid = arrayOfStrings[1];
				var hexTimeHigh = arrayOfStrings[2];
			
				// Chop off the leading "1" character, which is the UUID 
				// version number for time-based UUIDs.
				hexTimeHigh = hexTimeHigh.slice(1);
			
				this._timestampAsHexString = hexTimeHigh + hexTimeMid + hexTimeLow;
				dojo.lang.assert(this._timestampAsHexString.length == 15);
			}
			return this._timestampAsHexString;
			break;
		case null: // no returnType was specified, so default to Date
		case "date":
		case Date:
			// Return a JavaScript Date object. 
			if (!this._timestampAsDate) {
				var GREGORIAN_CHANGE_OFFSET_IN_HOURS = 3394248;
			
				var arrayOfParts = this._uuidString.split('-');
				var timeLow = parseInt(arrayOfParts[0], dojo.uuid.Uuid.HEX_RADIX);
				var timeMid = parseInt(arrayOfParts[1], dojo.uuid.Uuid.HEX_RADIX);
				var timeHigh = parseInt(arrayOfParts[2], dojo.uuid.Uuid.HEX_RADIX);
				var hundredNanosecondIntervalsSince1582 = timeHigh & 0x0FFF;
				hundredNanosecondIntervalsSince1582 <<= 16;
				hundredNanosecondIntervalsSince1582 += timeMid;
				// What we really want to do next is shift left 32 bits, but the 
				// result will be too big to fit in an int, so we'll multiply by 2^32,
				// and the result will be a floating point approximation.
				hundredNanosecondIntervalsSince1582 *= 0x100000000;
				hundredNanosecondIntervalsSince1582 += timeLow;
				var millisecondsSince1582 = hundredNanosecondIntervalsSince1582 / 10000;
			
				// Again, this will be a floating point approximation.
				// We can make things exact later if we need to.
				var secondsPerHour = 60 * 60;
				var hoursBetween1582and1970 = GREGORIAN_CHANGE_OFFSET_IN_HOURS;
				var secondsBetween1582and1970 = hoursBetween1582and1970 * secondsPerHour;
				var millisecondsBetween1582and1970 = secondsBetween1582and1970 * 1000;
				var millisecondsSince1970 = millisecondsSince1582 - millisecondsBetween1582and1970;
			
				this._timestampAsDate = new Date(millisecondsSince1970);
			}
			return this._timestampAsDate;
			break;
		default:
			// we got passed something other than a valid returnType
			dojo.lang.assert(false, "The getTimestamp() method dojo.uuid.Uuid was passed a bogus returnType: " + returnType);
			break;
	}
};
