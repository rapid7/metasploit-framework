/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.data.Observable");
dojo.require("dojo.lang.common");
dojo.require("dojo.lang.assert");

// -------------------------------------------------------------------
// Constructor
// -------------------------------------------------------------------
dojo.data.Observable = function() {
};

// -------------------------------------------------------------------
// Public instance methods
// -------------------------------------------------------------------
dojo.data.Observable.prototype.addObserver = function(/* object */ observer) {
	/**
	 * summary: Registers an object as an observer of this item,
	 * so that the object will be notified when the item changes.
	 */ 
	dojo.lang.assertType(observer, Object);
	dojo.lang.assertType(observer.observedObjectHasChanged, Function);
	if (!this._arrayOfObservers) {
		this._arrayOfObservers = [];
	}
	if (!dojo.lang.inArray(this._arrayOfObservers, observer)) {
		this._arrayOfObservers.push(observer);
	}
};

dojo.data.Observable.prototype.removeObserver = function(/* object */ observer) {
	/**
	 * summary: Removes the observer registration for a previously
	 * registered object.
	 */ 
	if (!this._arrayOfObservers) {
		return;
	}
	var index = dojo.lang.indexOf(this._arrayOfObservers, observer);
	if (index != -1) {
		this._arrayOfObservers.splice(index, 1);
	}
};

dojo.data.Observable.prototype.getObservers = function() {
	/**
	 * summary: Returns an array with all the observers of this item.
	 */ 
	return this._arrayOfObservers; // Array or undefined
};

