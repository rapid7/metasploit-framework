/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.ShowSlide");

dojo.require("dojo.widget.*");
dojo.require("dojo.lang.common");

dojo.widget.ShowSlide = function(){
}
dojo.lang.extend(dojo.widget.ShowSlide, {
	title: "",
	_action: -1,
	isContainer: true,
	_components: {},
	_actions: [],
	gotoAction: function(/*int*/ action){
		this._action = action;
	},
	nextAction: function(/*Event?*/ event){
		if((this._action + 1) != this._actions.length){
			++this._action;
			return true; // boolean
		}
		return false; // boolean
	},
	previousAction: function(/*Event?*/ event){
		if((this._action - 1) != -1){
			--this._action;
			return true; // boolean
		}
		return false; // boolean
	}
});

dojo.requireAfterIf("html", "dojo.widget.html.ShowSlide");