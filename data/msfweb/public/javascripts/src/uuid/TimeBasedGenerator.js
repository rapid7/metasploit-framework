/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.uuid.TimeBasedGenerator");
dojo.require("dojo.lang.*");

dojo.uuid.TimeBasedGenerator = new function() {

// --------------------------------------------------
// Public constants
// --------------------------------------------------
	// Number of hours between October 15, 1582 and January 1, 1970:
	this.GREGORIAN_CHANGE_OFFSET_IN_HOURS = 3394248;
	
	// Number of seconds between October 15, 1582 and January 1, 1970:
	//   this.GREGORIAN_CHANGE_OFFSET_IN_SECONDS = 12219292800;	
	
// --------------------------------------------------
// Private variables
// --------------------------------------------------
	var _uuidPseudoNodeString = null;
	var _uuidClockSeqString = null;
	var _dateValueOfPreviousUuid = null;
	var _nextIntraMillisecondIncrement = 0;
	var _cachedMillisecondsBetween1582and1970 = null;
	var _cachedHundredNanosecondIntervalsPerMillisecond = null;
	var _uniformNode = null;
	var HEX_RADIX = 16;

// --------------------------------------------------
// Private functions
// --------------------------------------------------

/**
 * Given an array which holds a 64-bit number broken into 4 16-bit elements,
 * this method carries any excess bits (greater than 16-bits) from each array
 * element into the next.
 *
 * @param	arrayA	An array with 4 elements, each of which is a 16-bit number.
 */
	function _carry(arrayA) {
		arrayA[2] += arrayA[3] >>> 16;
		arrayA[3] &= 0xFFFF;
		arrayA[1] += arrayA[2] >>> 16;
		arrayA[2] &= 0xFFFF;
		arrayA[0] += arrayA[1] >>> 16;
		arrayA[1] &= 0xFFFF;
		dojo.lang.assert((arrayA[0] >>> 16) === 0);
	}

/**
 * Given a floating point number, this method returns an array which holds a
 * 64-bit number broken into 4 16-bit elements.
 *
 * @param	x	A floating point number.
 * @return   An array with 4 elements, each of which is a 16-bit number.
 */
	function _get64bitArrayFromFloat(x) {
		var result = new Array(0, 0, 0, 0);
		result[3] = x % 0x10000;
		x -= result[3];
		x /= 0x10000;
		result[2] = x % 0x10000;
		x -= result[2];
		x /= 0x10000;
		result[1] = x % 0x10000;
		x -= result[1];
		x /= 0x10000;
		result[0] = x;
		return result;
	}

/**
 * Takes two arrays, each of which holds a 64-bit number broken into 4
 * 16-bit elements, and returns a new array that holds a 64-bit number
 * that is the sum of the two original numbers.
 *
 * @param	arrayA	An array with 4 elements, each of which is a 16-bit number.
 * @param	arrayB	An array with 4 elements, each of which is a 16-bit number.
 * @return   An array with 4 elements, each of which is a 16-bit number.
 */
	function _addTwo64bitArrays(arrayA, arrayB) {
		dojo.lang.assertType(arrayA, Array);
		dojo.lang.assertType(arrayB, Array);
		dojo.lang.assert(arrayA.length == 4);
		dojo.lang.assert(arrayB.length == 4);
	
		var result = new Array(0, 0, 0, 0);
		result[3] = arrayA[3] + arrayB[3];
		result[2] = arrayA[2] + arrayB[2];
		result[1] = arrayA[1] + arrayB[1];
		result[0] = arrayA[0] + arrayB[0];
		_carry(result);
		return result;
	}

/**
 * Takes two arrays, each of which holds a 64-bit number broken into 4
 * 16-bit elements, and returns a new array that holds a 64-bit number
 * that is the product of the two original numbers.
 *
 * @param	arrayA	An array with 4 elements, each of which is a 16-bit number.
 * @param	arrayB	An array with 4 elements, each of which is a 16-bit number.
 * @return   An array with 4 elements, each of which is a 16-bit number.
 */
	function _multiplyTwo64bitArrays(arrayA, arrayB) {
		dojo.lang.assertType(arrayA, Array);
		dojo.lang.assertType(arrayB, Array);
		dojo.lang.assert(arrayA.length == 4);
		dojo.lang.assert(arrayB.length == 4);
	
		var overflow = false;
		if (arrayA[0] * arrayB[0] !== 0) { overflow = true; }
		if (arrayA[0] * arrayB[1] !== 0) { overflow = true; }
		if (arrayA[0] * arrayB[2] !== 0) { overflow = true; }
		if (arrayA[1] * arrayB[0] !== 0) { overflow = true; }
		if (arrayA[1] * arrayB[1] !== 0) { overflow = true; }
		if (arrayA[2] * arrayB[0] !== 0) { overflow = true; }
		dojo.lang.assert(!overflow);
	
		var result = new Array(0, 0, 0, 0);
		result[0] += arrayA[0] * arrayB[3];
		_carry(result);
		result[0] += arrayA[1] * arrayB[2];
		_carry(result);
		result[0] += arrayA[2] * arrayB[1];
		_carry(result);
		result[0] += arrayA[3] * arrayB[0];
		_carry(result);
		result[1] += arrayA[1] * arrayB[3];
		_carry(result);
		result[1] += arrayA[2] * arrayB[2];
		_carry(result);
		result[1] += arrayA[3] * arrayB[1];
		_carry(result);
		result[2] += arrayA[2] * arrayB[3];
		_carry(result);
		result[2] += arrayA[3] * arrayB[2];
		_carry(result);
		result[3] += arrayA[3] * arrayB[3];
		_carry(result);
		return result;
	}

/**
 * Pads a string with leading zeros and returns the result.
 * For example:
 * <pre>
 *   result = _padWithLeadingZeros("abc", 6);
 *   dojo.lang.assert(result == "000abc");
 * </pre>
 *
 * @param	string	A string to add padding to.
 * @param	desiredLength	The number of characters the return string should have.
 * @return   A string.
 */
	function _padWithLeadingZeros(string, desiredLength) {
		while (string.length < desiredLength) {
			string = "0" + string;
		}
		return string;
	}

/**
 * Returns a randomly generated 8-character string of hex digits.
 *
 * @return   An 8-character hex string.
 */
	function _generateRandomEightCharacterHexString() {
		// FIXME: This probably isn't a very high quality random number.
	
		// Make random32bitNumber be a randomly generated floating point number
		// between 0 and (4,294,967,296 - 1), inclusive.
		var random32bitNumber = Math.floor( (Math.random() % 1) * Math.pow(2, 32) );
	
		var eightCharacterString = random32bitNumber.toString(HEX_RADIX);
		while (eightCharacterString.length < 8) {
			eightCharacterString = "0" + eightCharacterString;
		}
		return eightCharacterString;
	}

/**
 * Generates a time-based UUID, meaning a version 1 UUID.  JavaScript
 * code running in a browser doesn't have access to the IEEE 802.3 address
 * of the computer, so if a node value isn't supplied, we generate a random 
 * pseudonode value instead.
 *
 * @param	node	Optional. A 12-character string to use as the node in the new UUID.
 * @return   Returns a 36 character string, which will look something like "b4308fb0-86cd-11da-a72b-0800200c9a66".
 */
	function _generateUuidString(node) {
		dojo.lang.assertType(node, [String, "optional"]);
		if (node) {
			dojo.lang.assert(node.length == 12);
		} else {
			if (_uniformNode) {
				node = _uniformNode;
			} else {
				if (!_uuidPseudoNodeString) {
					var pseudoNodeIndicatorBit = 0x8000;
					var random15bitNumber = Math.floor( (Math.random() % 1) * Math.pow(2, 15) );
					var leftmost4HexCharacters = (pseudoNodeIndicatorBit | random15bitNumber).toString(HEX_RADIX);
					_uuidPseudoNodeString = leftmost4HexCharacters + _generateRandomEightCharacterHexString();
				}
				node = _uuidPseudoNodeString;
			}
		}
		if (!_uuidClockSeqString) {
			var variantCodeForDCEUuids = 0x8000; // 10--------------, i.e. uses only first two of 16 bits.
			var random14bitNumber = Math.floor( (Math.random() % 1) * Math.pow(2, 14) );
			_uuidClockSeqString = (variantCodeForDCEUuids | random14bitNumber).toString(HEX_RADIX);
		}
	
		// Maybe we should think about trying to make the code more readable to
		// newcomers by creating a class called "WholeNumber" that encapsulates
		// the methods and data structures for working with these arrays that
		// hold 4 16-bit numbers?  And then these variables below have names
		// like "wholeSecondsPerHour" rather than "arraySecondsPerHour"?
		var now = new Date();
		var millisecondsSince1970 = now.valueOf(); // milliseconds since midnight 01 January, 1970 UTC.
		var nowArray = _get64bitArrayFromFloat(millisecondsSince1970);
		if (!_cachedMillisecondsBetween1582and1970) {
			var arraySecondsPerHour = _get64bitArrayFromFloat(60 * 60);
			var arrayHoursBetween1582and1970 = _get64bitArrayFromFloat(dojo.uuid.TimeBasedGenerator.GREGORIAN_CHANGE_OFFSET_IN_HOURS);
			var arraySecondsBetween1582and1970 = _multiplyTwo64bitArrays(arrayHoursBetween1582and1970, arraySecondsPerHour);
			var arrayMillisecondsPerSecond = _get64bitArrayFromFloat(1000);
			_cachedMillisecondsBetween1582and1970 = _multiplyTwo64bitArrays(arraySecondsBetween1582and1970, arrayMillisecondsPerSecond);
			_cachedHundredNanosecondIntervalsPerMillisecond = _get64bitArrayFromFloat(10000);
		}
		var arrayMillisecondsSince1970 = nowArray;
		var arrayMillisecondsSince1582 = _addTwo64bitArrays(_cachedMillisecondsBetween1582and1970, arrayMillisecondsSince1970);
		var arrayHundredNanosecondIntervalsSince1582 = _multiplyTwo64bitArrays(arrayMillisecondsSince1582, _cachedHundredNanosecondIntervalsPerMillisecond);
	
		if (now.valueOf() == _dateValueOfPreviousUuid) {
			arrayHundredNanosecondIntervalsSince1582[3] += _nextIntraMillisecondIncrement;
			_carry(arrayHundredNanosecondIntervalsSince1582);
			_nextIntraMillisecondIncrement += 1;
			if (_nextIntraMillisecondIncrement == 10000) {
				// If we've gotten to here, it means we've already generated 10,000
				// UUIDs in this single millisecond, which is the most that the UUID
				// timestamp field allows for.  So now we'll just sit here and wait
				// for a fraction of a millisecond, so as to ensure that the next
				// time this method is called there will be a different millisecond
				// value in the timestamp field.
				while (now.valueOf() == _dateValueOfPreviousUuid) {
					now = new Date();
				}
			}
		} else {
			_dateValueOfPreviousUuid = now.valueOf();
			_nextIntraMillisecondIncrement = 1;
		}
	
		var hexTimeLowLeftHalf  = arrayHundredNanosecondIntervalsSince1582[2].toString(HEX_RADIX);
		var hexTimeLowRightHalf = arrayHundredNanosecondIntervalsSince1582[3].toString(HEX_RADIX);
		var hexTimeLow = _padWithLeadingZeros(hexTimeLowLeftHalf, 4) + _padWithLeadingZeros(hexTimeLowRightHalf, 4);
		var hexTimeMid = arrayHundredNanosecondIntervalsSince1582[1].toString(HEX_RADIX);
		hexTimeMid = _padWithLeadingZeros(hexTimeMid, 4);
		var hexTimeHigh = arrayHundredNanosecondIntervalsSince1582[0].toString(HEX_RADIX);
		hexTimeHigh = _padWithLeadingZeros(hexTimeHigh, 3);
		var hyphen = "-";
		var versionCodeForTimeBasedUuids = "1"; // binary2hex("0001")
		var resultUuid = hexTimeLow + hyphen + hexTimeMid + hyphen +
					versionCodeForTimeBasedUuids + hexTimeHigh + hyphen +
					_uuidClockSeqString + hyphen + node;
		resultUuid = resultUuid.toLowerCase();
		return resultUuid;
	}

// --------------------------------------------------
// Public functions
// --------------------------------------------------

/**
 * Sets the 'node' value that will be included in generated UUIDs.
 *
 * @param	node	A 12-character hex string representing a pseudoNode or hardwareNode.
 */
	this.setNode = function(node) {
		dojo.lang.assert((node === null) || (node.length == 12));
		_uniformNode = node;
	};

/**
 * Returns the 'node' value that will be included in generated UUIDs.
 *
 * @return	A 12-character hex string representing a pseudoNode or hardwareNode.
 */
	this.getNode = function() {
		return _uniformNode;
	};

/**
 * This function generates time-based UUIDs, meaning "version 1" UUIDs.
 *
 * For more info, see
 *   http://www.webdav.org/specs/draft-leach-uuids-guids-01.txt
 *   http://www.infonuovo.com/dma/csdocs/sketch/instidid.htm
 *   http://kruithof.xs4all.nl/uuid/uuidgen
 *   http://www.opengroup.org/onlinepubs/009629399/apdxa.htm#tagcjh_20
 *   http://jakarta.apache.org/commons/sandbox/id/apidocs/org/apache/commons/id/uuid/clock/Clock.html
 *
 * Examples:
 * <pre>
 *   var generate = dojo.uuid.TimeBasedGenerator.generate;
 *   var uuid;   // an instance of dojo.uuid.Uuid
 *   var string; // a simple string literal
 *   string = generate();
 *   string = generate(String);
 *   uuid   = generate(dojo.uuid.Uuid);
 *   string = generate("017bf397618a");
 *   string = generate({node: "017bf397618a"});         // hardwareNode
 *   string = generate({node: "f17bf397618a"});         // pseudoNode
 *   string = generate({hardwareNode: "017bf397618a"});
 *   string = generate({pseudoNode:   "f17bf397618a"});
 *   string = generate({node: "017bf397618a", returnType: String});
 *   uuid   = generate({node: "017bf397618a", returnType: dojo.uuid.Uuid});
 *   dojo.uuid.TimeBasedGenerator.setNode("017bf397618a");
 *   string = generate(); // the generated UUID has node == "017bf397618a"
 *   uuid   = generate(dojo.uuid.Uuid); // the generated UUID has node == "017bf397618a"
 * </pre>
 *
 * @param	class	The type of instance to return.
 * @param	node	A 12-character hex string representing a pseudoNode or hardwareNode.
 * @namedParam	node	A 12-character hex string representing a pseudoNode or hardwareNode.
 * @namedParam	hardwareNode	A 12-character hex string containing an IEEE 802.3 network node identificator.
 * @namedParam	pseudoNode	A 12-character hex string representing a pseudoNode.
 * @namedParam	returnType	The type of instance to return.
 * @return	A newly generated version 1 UUID.
 */
	this.generate = function(input) {
		var nodeString = null;
		var returnType = null;
		
		if (input) {
			if (dojo.lang.isObject(input) && !dojo.lang.isBuiltIn(input)) {
				var namedParameters = input;
				dojo.lang.assertValidKeywords(namedParameters, ["node", "hardwareNode", "pseudoNode", "returnType"]);
				var node = namedParameters["node"];
				var hardwareNode = namedParameters["hardwareNode"];
				var pseudoNode = namedParameters["pseudoNode"];
				nodeString = (node || pseudoNode || hardwareNode);
				if (nodeString) {
					var firstCharacter = nodeString.charAt(0);
					var firstDigit = parseInt(firstCharacter, HEX_RADIX);
					if (hardwareNode) {
						dojo.lang.assert((firstDigit >= 0x0) && (firstDigit <= 0x7));
					}
					if (pseudoNode) {
						dojo.lang.assert((firstDigit >= 0x8) && (firstDigit <= 0xF));
					}
				}
				returnType = namedParameters["returnType"];
				dojo.lang.assertType(returnType, [Function, "optional"]);
			} else {
				if (dojo.lang.isString(input)) {
					nodeString = input;
					returnType = null;
				} else {
					if (dojo.lang.isFunction(input)) {
						nodeString = null;
						returnType = input;
					}
				}
			}
			if (nodeString) {
				dojo.lang.assert(nodeString.length == 12);
				var integer = parseInt(nodeString, HEX_RADIX);
				dojo.lang.assert(isFinite(integer));
			}
			dojo.lang.assertType(returnType, [Function, "optional"]);
		}
		
		var uuidString = _generateUuidString(nodeString);
		var returnValue;
		if (returnType && (returnType != String)) {
			returnValue = new returnType(uuidString);
		} else {
			returnValue = uuidString;
		}
		return returnValue;
	};
}();
