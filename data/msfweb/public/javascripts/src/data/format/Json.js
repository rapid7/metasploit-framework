/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.data.format.Json");
dojo.require("dojo.lang.assert");

dojo.data.format.Json = new function() {

	// -------------------------------------------------------------------
	// Public functions
	// -------------------------------------------------------------------
	this.loadDataProviderFromFileContents = function(/* dojo.data.provider.Base */ dataProvider, /* string */ jsonFileContents) {
		dojo.lang.assertType(dataProvider, dojo.data.provider.Base);
		dojo.lang.assertType(jsonFileContents, String);
		var arrayOfJsonData = eval("(" + jsonFileContents + ")");
		this.loadDataProviderFromArrayOfJsonData(dataProvider, arrayOfJsonData);
	};
	
	this.loadDataProviderFromArrayOfJsonData = function(/* dojo.data.provider.Base */ dataProvider, /* Array */ arrayOfJsonData) {
		dojo.lang.assertType(arrayOfJsonData, [Array, "optional"]);
		if (arrayOfJsonData && (arrayOfJsonData.length > 0)) {
			var firstRow = arrayOfJsonData[0];
			dojo.lang.assertType(firstRow, [Array, "pureobject"]);
			if (dojo.lang.isArray(firstRow)) {
				_loadDataProviderFromArrayOfArrays(dataProvider, arrayOfJsonData);
			} else {
				dojo.lang.assertType(firstRow, "pureobject");
				_loadDataProviderFromArrayOfObjects(dataProvider, arrayOfJsonData);
			}
		}
	};

	this.getJsonStringFromResultSet = function(/* dojo.data.ResultSet */ resultSet) {
		dojo.unimplemented('dojo.data.format.Json.getJsonStringFromResultSet');
		var jsonString = null;
		return jsonString; // String
	};

	// -------------------------------------------------------------------
	// Private functions
	// -------------------------------------------------------------------
	function _loadDataProviderFromArrayOfArrays(/* dojo.data.provider.Base */ dataProvider, /* Array */ arrayOfJsonData) {
		/** 
		 * Example: 
		 * var arrayOfJsonStates = [
		 * 	 [ "abbr",  "population",  "name" ]
		 * 	 [  "WA",     5894121,      "Washington"    ],
		 * 	 [  "WV",     1808344,      "West Virginia" ],
		 * 	 [  "WI",     5453896,      "Wisconsin"     ],
		 *   [  "WY",      493782,      "Wyoming"       ] ];
		 * this._loadFromArrayOfArrays(arrayOfJsonStates);
		 */
		var arrayOfKeys = arrayOfJsonData[0];
		for (var i = 1; i < arrayOfJsonData.length; ++i) {
			var row = arrayOfJsonData[i];
			var item = dataProvider.getNewItemToLoad();
			for (var j in row) {
				var value = row[j];
				var key = arrayOfKeys[j];
				item.load(key, value);
			}
		}
	}

	function _loadDataProviderFromArrayOfObjects(/* dojo.data.provider.Base */ dataProvider, /* Array */ arrayOfJsonData) {
		/** 
		 * Example: 
		 * var arrayOfJsonStates = [
		 * 	 { abbr: "WA", name: "Washington" },
		 * 	 { abbr: "WV", name: "West Virginia" },
		 * 	 { abbr: "WI", name: "Wisconsin", song: "On, Wisconsin!" },
		 * 	 { abbr: "WY", name: "Wyoming", cities: ["Lander", "Cheyenne", "Laramie"] } ];
		 * this._loadFromArrayOfArrays(arrayOfJsonStates);
		 */
		// dojo.debug("_loadDataProviderFromArrayOfObjects");
		for (var i in arrayOfJsonData) {
			var row = arrayOfJsonData[i];
			var item = dataProvider.getNewItemToLoad();
			for (var key in row) {
				var value = row[key];
				if (dojo.lang.isArray(value)) {
					var arrayOfValues = value;
					for (var j in arrayOfValues) {
						value = arrayOfValues[j];
						item.load(key, value);
						// dojo.debug("loaded: " + key + " = " + value); 
					}
				} else {
					item.load(key, value);
				}
			}
		}
	}
	
}();

