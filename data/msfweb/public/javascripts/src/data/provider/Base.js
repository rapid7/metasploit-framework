/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.data.provider.Base");
dojo.require("dojo.lang.assert");

// -------------------------------------------------------------------
// Constructor
// -------------------------------------------------------------------
dojo.data.provider.Base = function() {
	/**
	 * summary:
	 * A Data Provider serves as a connection to some data source,
	 * like a relational database.  This data provider Base class
	 * serves as an abstract superclass for other data provider
	 * classes.
	 */
	this._countOfNestedTransactions = 0;
	this._changesInCurrentTransaction = null;
};

// -------------------------------------------------------------------
// Public instance methods
// -------------------------------------------------------------------
dojo.data.provider.Base.prototype.beginTransaction = function() {
	/**
	 * Marks the beginning of a transaction.
	 *
	 * Each time you call beginTransaction() you open a new transaction, 
	 * which you need to close later using endTransaction().  Transactions
	 * may be nested, but the beginTransaction and endTransaction calls
	 * always need to come in pairs.
	 */
	if (this._countOfNestedTransactions === 0) {
		this._changesInCurrentTransaction = [];
	}
	this._countOfNestedTransactions += 1;
};

dojo.data.provider.Base.prototype.endTransaction = function() {
	/**
	 * Marks the end of a transaction.
	 */
	this._countOfNestedTransactions -= 1;
	dojo.lang.assert(this._countOfNestedTransactions >= 0);

	if (this._countOfNestedTransactions === 0) {
		var listOfChangesMade = this._saveChanges();
		this._changesInCurrentTransaction = null;
		if (listOfChangesMade.length > 0) {
			// dojo.debug("endTransaction: " + listOfChangesMade.length + " changes made");
			this._notifyObserversOfChanges(listOfChangesMade);
		}
	}
};

dojo.data.provider.Base.prototype.getNewItemToLoad = function() {
	return this._newItem(); // dojo.data.Item
};

dojo.data.provider.Base.prototype.newItem = function(/* string */ itemName) {
	/**
	 * Creates a new item.
	 */
	dojo.lang.assertType(itemName, [String, "optional"]);
	var item = this._newItem();
	if (itemName) {
		item.set('name', itemName);
	}
	return item; // dojo.data.Item
};

dojo.data.provider.Base.prototype.newAttribute = function(/* string */ attributeId) {
	/**
	 * Creates a new attribute.
	 */
	dojo.lang.assertType(attributeId, String); // FIXME: should be optional
	var attribute = this._newAttribute(attributeId);
	return attribute; // dojo.data.Attribute
};

dojo.data.provider.Base.prototype.getAttribute = function(/* string */ attributeId) {
	dojo.unimplemented('dojo.data.provider.Base');
	var attribute;
	return attribute; // dojo.data.Attribute
};

dojo.data.provider.Base.prototype.getAttributes = function() {
	dojo.unimplemented('dojo.data.provider.Base');
	return this._arrayOfAttributes; // Array
};

dojo.data.provider.Base.prototype.fetchArray = function() {
	dojo.unimplemented('dojo.data.provider.Base');
	return []; // Array
};

dojo.data.provider.Base.prototype.fetchResultSet = function() {
	dojo.unimplemented('dojo.data.provider.Base');
	var resultSet;
	return resultSet; // dojo.data.ResultSet
};

dojo.data.provider.Base.prototype.noteChange = function(/* dojo.data.Item */ item, /* string or dojo.data.Attribute */ attribute, /* anything */ value) {
	var change = {item: item, attribute: attribute, value: value};
	if (this._countOfNestedTransactions === 0) {
		this.beginTransaction();
		this._changesInCurrentTransaction.push(change);
		this.endTransaction();
	} else {
		this._changesInCurrentTransaction.push(change);
	}
};

dojo.data.provider.Base.prototype.addItemObserver = function(/* dojo.data.Item */ item, /* object */ observer) {
	/**
	 * summary: Registers an object as an observer of an item,
	 * so that the object will be notified when the item changes.
	 */
	dojo.lang.assertType(item, dojo.data.Item);
	item.addObserver(observer);
};

dojo.data.provider.Base.prototype.removeItemObserver = function(/* dojo.data.Item */ item, /* object */ observer) {
	/**
	 * summary: Removes the observer registration for a previously
	 * registered object.
	 */ 
	dojo.lang.assertType(item, dojo.data.Item);
	item.removeObserver(observer);
};

// -------------------------------------------------------------------
// Private instance methods
// -------------------------------------------------------------------
dojo.data.provider.Base.prototype._newItem = function() {
	var item = new dojo.data.Item(this);
	return item; // dojo.data.Item
};

dojo.data.provider.Base.prototype._newAttribute = function(/* String */ attributeId) {
	var attribute = new dojo.data.Attribute(this);
	return attribute; // dojo.data.Attribute
};

dojo.data.provider.Base.prototype._saveChanges = function() {
	var arrayOfChangesMade = this._changesInCurrentTransaction;
	return arrayOfChangesMade; // Array
};

dojo.data.provider.Base.prototype._notifyObserversOfChanges = function(/* Array */ arrayOfChanges) {
	var arrayOfResultSets = this._getResultSets();
	for (var i in arrayOfChanges) {
		var change = arrayOfChanges[i];
		var changedItem = change.item;
		var arrayOfItemObservers = changedItem.getObservers();
		for (var j in arrayOfItemObservers) {
			var observer = arrayOfItemObservers[j];
			observer.observedObjectHasChanged(changedItem, change);
		}
		for (var k in arrayOfResultSets) {
			var resultSet = arrayOfResultSets[k];
			var arrayOfResultSetObservers = resultSet.getObservers();
			for (var m in arrayOfResultSetObservers) {
				observer = arrayOfResultSetObservers[m];
				observer.observedObjectHasChanged(resultSet, change);
			}
		}
	}
};

dojo.data.provider.Base.prototype._getResultSets = function() {
	dojo.unimplemented('dojo.data.provider.Base');
	return []; // Array
};

