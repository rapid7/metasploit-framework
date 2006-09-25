/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.Show");

dojo.require("dojo.widget.*");
dojo.require("dojo.lang.common");

dojo.widget.Show = function(){}
dojo.lang.extend(dojo.widget.Show, {
	isContainer: true,
	_slide: -1,
	_slides: [],
	gotoSlide: function(/*int*/ slide){
		this._slide = slide;
		// summary: Placeholder
	},
	nextSlide: function(/*Event?*/ event){
		if(!this._slides[this._slide].nextAction(event)){
			if((this._slide + 1) != this._slides.length){
				this.gotoSlide(this._slide + 1);
				return true; // boolean
			}
			return false; // boolean
		}
	},
	previousSlide: function(/*Event?*/ event){
		if(!this._slides[this._slide].previousAction(event)){
			if((this._slide - 1) != -1){
				this.gotoSlide(this._slide - 1);
				return true; // boolean
			}
			return false; // boolean
		}
	}
});

dojo.requireAfterIf("html", "dojo.widget.html.Show");