/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

// FIXME: not yet functional

dojo.provide("dojo.widget.SvgButton");

dojo.require("dojo.widget.Button");

dojo.widget.SvgButton = function(){
	// FIXME: this is incomplete and doesn't work yet
	// if DOMButton turns into a mixin, we should subclass Button instead and
	// just mix in the DOMButton properties.

	dojo.widget.DomButton.call(this);
	dojo.widget.SvgWidget.call(this);

	// FIXME: freaking implement this already!
	this.onFoo = function(){ alert("bar"); }

	this.label = "huzzah!";

	this.setLabel = function(x, y, textSize, label, shape){
		//var labelNode = this.domNode.ownerDocument.createTextNode(this.label);
		//var textNode = this.domNode.ownerDocument.createElement("text");
		var coords = dojo.widget.SvgButton.prototype.coordinates(x, y, textSize, label, shape);
		var textString = "";
		switch(shape) {
			case "ellipse":
				textString = "<text x='"+ coords[6] + "' y='"+ coords[7] + "'>"+ label + "</text>";
				//textNode.setAttribute("x", coords[6]);
				//textNode.setAttribute("y", coords[7]);
				break;
			case "rectangle":
				//FIXME: implement
				textString = "";
				//textNode.setAttribute("x", coords[6]);
				//textNode.setAttribute("y", coords[7]);
				break;
			case "circle":
				//FIXME: implement
				textString = "";
				//textNode.setAttribute("x", coords[6]);
				//textNode.setAttribute("y", coords[7]);
				break;
		}
		//textNode.appendChild(labelNode);
		//this.domNode.appendChild(textNode);
		return textString;
		//alert(textNode.getComputedTextLength());
	}

	this.fillInTemplate = function(x, y, textSize, label, shape){
		// the idea is to set the text to the appropriate place given its length
		// and the template shape
		
		// FIXME: For now, assuming text sizes are integers in SVG units
		this.textSize = textSize || 12;
		this.label = label;
		// FIXEME: for now, I'm going to fake this... need to come up with a real way to 
		// determine the actual width of the text, such as computedStyle
		var textWidth = this.label.length*this.textSize ;
		//this.setLabel();
	}
}

dojo.inherits(dojo.widget.SvgButton, dojo.widget.DomButton);

// FIXME
dojo.widget.SvgButton.prototype.shapeString = function(x, y, textSize, label, shape) {
	switch(shape) {
		case "ellipse":
			var coords = dojo.widget.SvgButton.prototype.coordinates(x, y, textSize, label, shape)
			return "<ellipse cx='"+ coords[4]+"' cy='"+ coords[5]+"' rx='"+ coords[2]+"' ry='"+ coords[3]+"'/>";
			break;
		case "rect":
			//FIXME: implement
			return "";
			//return "<rect x='110' y='45' width='70' height='30'/>";
			break;
		case "circle":
			//FIXME: implement
			return "";
			//return "<circle cx='210' cy='60' r='23'/>";
			break;
	}
}

dojo.widget.SvgButton.prototype.coordinates = function(x, y, textSize, label, shape) {
	switch(shape) {
		case "ellipse":
			var buttonWidth = label.length*textSize;
			var buttonHeight = textSize*2.5
			var rx = buttonWidth/2;
			var ry = buttonHeight/2;
			var cx = rx + x;
			var cy = ry + y;
			var textX = cx - rx*textSize/25;
			var textY = cy*1.1;
			return [buttonWidth, buttonHeight, rx, ry, cx, cy, textX, textY];
			break;
		case "rectangle":
			//FIXME: implement
			return "";
			break;
		case "circle":
			//FIXME: implement
			return "";
			break;
	}
}

dojo.widget.SvgButton.prototype.labelString = function(x, y, textSize, label, shape){
	var textString = "";
	var coords = dojo.widget.SvgButton.prototype.coordinates(x, y, textSize, label, shape);
	switch(shape) {
		case "ellipse":
			textString = "<text x='"+ coords[6] + "' y='"+ coords[7] + "'>"+ label + "</text>";
			break;
		case "rectangle":
			//FIXME: implement
			textString = "";
			break;
		case "circle":
			//FIXME: implement
			textString = "";
			break;
	}
	return textString;
}

dojo.widget.SvgButton.prototype.templateString = function(x, y, textSize, label, shape) {
	return "<g class='dojoButton' dojoAttachEvent='onClick; onMouseMove: onFoo;' dojoAttachPoint='labelNode'>"+ dojo.widgets.SVGButton.prototype.shapeString(x, y, textSize, label, shape) + dojo.widget.SVGButton.prototype.labelString(x, y, textSize, label, shape) + "</g>";
}
