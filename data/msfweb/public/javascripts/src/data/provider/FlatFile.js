/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.data.provider.FlatFile");
dojo.require("dojo.data.provider.Base");
dojo.require("dojo.data.Item");
dojo.require("dojo.data.Attribute");
dojo.require("dojo.data.ResultSet");
dojo.require("dojo.data.format.Json");
dojo.require("dojo.data.format.Csv");
dojo.require("dojo.lang.assert");

// -------------------------------------------------------------------
// Constructor
// -------------------------------------------------------------------
dojo.data.provider.FlatFile = function(/* keywords */ keywordParameters) {
	/**
	 * summary:
	 * A Json Data Provider knows how to read in simple JSON data
	 * tables and make their contents accessable as Items.
	 */
	dojo.lang.assertType(keywordParameters, ["pureobject", "optional"]);
	dojo.data.provider.Base.call(this);
	this._arrayOfItems = [];
	this._resultSet = null;
	this._dictionaryOfAttributes = {};

	if (keywordParameters) {
		var jsonObjects = keywordParameters["jsonObjects"];
		var jsonString  = keywordParameters["jsonString"];
		var fileUrl     = keywordParameters["url"];
		if (jsonObjects) {
			dojo.data.format.Json.loadDataProviderFromArrayOfJsonData(this, jsonObjects);
		}
		if (jsonString) {
			dojo.data.format.Json.loadDataProviderFromFileContents(this, jsonString);
		}
		if (fileUrl) {
			var arrayOfParts = fileUrl.split('.');
			var lastPart = arrayOfParts[(arrayOfParts.length - 1)];
			var formatParser = null;
			if (lastPart == "json") {
				formatParser = dojo.data.format.Json;
			}
			if (lastPart == "csv") {
				formatParser = dojo.data.format.Csv;
			}
			if (formatParser) {
				var fileContents = dojo.hostenv.getText(fileUrl);
				formatParser.loadDataProviderFromFileContents(this, fileContents);
			} else {
				dojo.lang.assert(false, "new dojo.data.provider.FlatFile({url: }) was passed a file without a .csv or .json suffix");
			}
		}
	}
};
dojo.inherits(dojo.data.provider.FlatFile, dojo.data.provider.Base);

// -------------------------------------------------------------------
// Public instance methods
// -------------------------------------------------------------------
dojo.data.provider.FlatFile.prototype.getProviderCapabilities = function(/* string */ keyword) {
	dojo.lang.assertType(keyword, [String, "optional"]);
	if (!this._ourCapabilities) {
		this._ourCapabilities = {
			transactions: false,
			undo: false,
			login: false,
			versioning: false,
			anonymousRead: true,
			anonymousWrite: false,
			permissions: false,
			queries: false,
			strongTyping: false,
			datatypes: [String, Date, Number]
		};
	}
	if (keyword) {
		return this._ourCapabilities[keyword];
	} else {
		return this._ourCapabilities;
	}
};

dojo.data.provider.FlatFile.prototype.registerAttribute = function(/* string or dojo.data.Attribute */ attributeId) {
	var registeredAttribute = this.getAttribute(attributeId);
	if (!registeredAttribute) {
		var newAttribute = new dojo.data.Attribute(this, attributeId);
		this._dictionaryOfAttributes[attributeId] = newAttribute;
		registeredAttribute = newAttribute;
	}
	return registeredAttribute; // dojo.data.Attribute
};

dojo.data.provider.FlatFile.prototype.getAttribute = function(/* string or dojo.data.Attribute */ attributeId) {
	var attribute = (this._dictionaryOfAttributes[attributeId] || null);
	return attribute; // dojo.data.Attribute or null
};

dojo.data.provider.FlatFile.prototype.getAttributes = function() {
	var arrayOfAttributes = [];
	for (var key in this._dictionaryOfAttributes) {
		var attribute = this._dictionaryOfAttributes[key];
		arrayOfAttributes.push(attribute);
	}
	return arrayOfAttributes; // Array
};

dojo.data.provider.FlatFile.prototype.fetchArray = function(query) {
	/**
	 * summary: Returns an Array containing all of the Items.
	 */ 
	return this._arrayOfItems; // Array
};

dojo.data.provider.FlatFile.prototype.fetchResultSet = function(query) {
	/**
	 * summary: Returns a ResultSet containing all of the Items.
	 */ 
	if (!this._resultSet) {
		this._resultSet = new dojo.data.ResultSet(this, this.fetchArray(query));
	}
	return this._resultSet; // dojo.data.ResultSet
};

// -------------------------------------------------------------------
// Private instance methods
// -------------------------------------------------------------------
dojo.data.provider.FlatFile.prototype._newItem = function() {
	var item = new dojo.data.Item(this);
	this._arrayOfItems.push(item);
	return item; // dojo.data.Item
};

dojo.data.provider.FlatFile.prototype._newAttribute = function(/* String */ attributeId) {
	dojo.lang.assertType(attributeId, String);
	dojo.lang.assert(this.getAttribute(attributeId) === null);
	var attribute = new dojo.data.Attribute(this, attributeId);
	this._dictionaryOfAttributes[attributeId] = attribute;
	return attribute; // dojo.data.Attribute
};

dojo.data.provider.Base.prototype._getResultSets = function() {
	return [this._resultSet]; // Array
};

