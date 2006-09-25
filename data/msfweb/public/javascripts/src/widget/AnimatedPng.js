/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.AnimatedPng");
dojo.provide("dojo.widget.html.AnimatedPng");

dojo.require("dojo.widget.*");
dojo.require("dojo.widget.HtmlWidget");


dojo.widget.defineWidget(
	"dojo.widget.html.AnimatedPng",
	dojo.widget.HtmlWidget,
	{

		widgetType: "AnimatedPng",
		isContainer: false,

		domNode: null,
		width: 0,
		height: 0,
		aniSrc: '',
		interval: 100,

		cellWidth: 0,
		cellHeight: 0,
		aniCols: 1,
		aniRows: 1,
		aniCells: 1,

		blankSrc: dojo.uri.dojoUri("src/widget/templates/images/blank.gif"),

		templateString: '<img class="dojoAnimatedPng" />',

		postCreate: function(){
			this.cellWidth = this.width;
			this.cellHeight = this.height;

			var img = new Image();
			var self = this;

			img.onload = function(){ self.initAni(img.width, img.height); };
			img.src = this.aniSrc;
		},

		initAni: function(w, h){

			this.domNode.src = this.blankSrc;
			this.domNode.width = this.cellWidth;
			this.domNode.height = this.cellHeight;
			this.domNode.style.backgroundImage = 'url('+this.aniSrc+')';
			this.domNode.style.backgroundRepeat = 'no-repeat';

			this.aniCols = Math.floor(w/this.cellWidth);
			this.aniRows = Math.floor(h/this.cellHeight);
			this.aniCells = this.aniCols * this.aniRows;
			this.aniFrame = 0;

			window.setInterval(dojo.lang.hitch(this, 'tick'), this.interval);
		},

		tick: function(){

			this.aniFrame++;
			if (this.aniFrame == this.aniCells) this.aniFrame = 0;

			var col = this.aniFrame % this.aniCols;
			var row = Math.floor(this.aniFrame / this.aniCols);

			var bx = -1 * col * this.cellWidth;
			var by = -1 * row * this.cellHeight;

			this.domNode.style.backgroundPosition = bx+'px '+by+'px';
		}
	}
);
