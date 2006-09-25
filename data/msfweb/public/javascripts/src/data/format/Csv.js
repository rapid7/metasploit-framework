/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.data.format.Csv");
dojo.require("dojo.lang.assert");


dojo.data.format.Csv = new function() {

	// -------------------------------------------------------------------
	// Public functions
	// -------------------------------------------------------------------
	this.getArrayStructureFromCsvFileContents = function(/* string */ csvFileContents) {
		/**
		 * Given a string containing CSV records, this method parses
		 * the string and returns a data structure containing the parsed
		 * content.  The data structure we return is an array of length
		 * R, where R is the number of rows (lines) in the CSV data.  The 
		 * return array contains one sub-array for each CSV line, and each 
		 * sub-array contains C string values, where C is the number of 
		 * columns in the CSV data.
		 * 
		 * For example, given this CSV string as input:
		 * <pre>
		 *   "Title, Year, Producer \n Alien, 1979, Ridley Scott \n Blade Runner, 1982, Ridley Scott"
		 * </pre>
		 * We will return this data structure:
		 * <pre>
		 *   [["Title", "Year", "Producer"]
		 *    ["Alien", "1979", "Ridley Scott"],  
		 *    ["Blade Runner", "1982", "Ridley Scott"]]
		 * </pre>
		 */
		dojo.lang.assertType(csvFileContents, String);
		
		var lineEndingCharacters = new RegExp("\r\n|\n|\r");
		var leadingWhiteSpaceCharacters = new RegExp("^\\s+",'g');
		var trailingWhiteSpaceCharacters = new RegExp("\\s+$",'g');
		var doubleQuotes = new RegExp('""','g');
		var arrayOfOutputRecords = [];
		
		var arrayOfInputLines = csvFileContents.split(lineEndingCharacters);
		for (var i in arrayOfInputLines) {
			var singleLine = arrayOfInputLines[i];
			if (singleLine.length > 0) {
				var listOfFields = singleLine.split(',');
				var j = 0;
				while (j < listOfFields.length) {
					var space_field_space = listOfFields[j];
					var field_space = space_field_space.replace(leadingWhiteSpaceCharacters, ''); // trim leading whitespace
					var field = field_space.replace(trailingWhiteSpaceCharacters, ''); // trim trailing whitespace
					var firstChar = field.charAt(0);
					var lastChar = field.charAt(field.length - 1);
					var secondToLastChar = field.charAt(field.length - 2);
					var thirdToLastChar = field.charAt(field.length - 3);
					if ((firstChar == '"') && 
							((lastChar != '"') || 
							 ((lastChar == '"') && (secondToLastChar == '"') && (thirdToLastChar != '"')) )) {
						if (j+1 === listOfFields.length) {
							// alert("The last field in record " + i + " is corrupted:\n" + field);
							return null;
						}
						var nextField = listOfFields[j+1];
						listOfFields[j] = field_space + ',' + nextField;
						listOfFields.splice(j+1, 1); // delete element [j+1] from the list
					} else {
						if ((firstChar == '"') && (lastChar == '"')) {
							field = field.slice(1, (field.length - 1)); // trim the " characters off the ends
							field = field.replace(doubleQuotes, '"');   // replace "" with "
						}
						listOfFields[j] = field;
						j += 1;
					}
				}
				arrayOfOutputRecords.push(listOfFields);
			}
		}
		return arrayOfOutputRecords; // Array
	};

	this.loadDataProviderFromFileContents = function(/* dojo.data.provider.Base */ dataProvider, /* string */ csvFileContents) {
		dojo.lang.assertType(dataProvider, dojo.data.provider.Base);
		dojo.lang.assertType(csvFileContents, String);
		var arrayOfArrays = this.getArrayStructureFromCsvFileContents(csvFileContents);
		if (arrayOfArrays) {
			var arrayOfKeys = arrayOfArrays[0];
			for (var i = 1; i < arrayOfArrays.length; ++i) {
				var row = arrayOfArrays[i];
				var item = dataProvider.getNewItemToLoad();
				for (var j in row) {
					var value = row[j];
					var key = arrayOfKeys[j];
					item.load(key, value);
				}
			}
		}
	};
	
	this.getCsvStringFromResultSet = function(/* dojo.data.ResultSet */ resultSet) {
		dojo.unimplemented('dojo.data.format.Csv.getCsvStringFromResultSet');
		var csvString = null;
		return csvString; // String
	};
	
}();
