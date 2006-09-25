/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.xml.domUtil");
dojo.require("dojo.graphics.color");
dojo.require("dojo.dom");
dojo.require("dojo.style");

dojo.deprecated("dojo.xml.domUtil", "use dojo.dom instead", "0.4");

// for loading script:
dojo.xml.domUtil = new function(){
	this.nodeTypes = {
		ELEMENT_NODE                  : 1,
		ATTRIBUTE_NODE                : 2,
		TEXT_NODE                     : 3,
		CDATA_SECTION_NODE            : 4,
		ENTITY_REFERENCE_NODE         : 5,
		ENTITY_NODE                   : 6,
		PROCESSING_INSTRUCTION_NODE   : 7,
		COMMENT_NODE                  : 8,
		DOCUMENT_NODE                 : 9,
		DOCUMENT_TYPE_NODE            : 10,
		DOCUMENT_FRAGMENT_NODE        : 11,
		NOTATION_NODE                 : 12
	}
	
	this.dojoml = "http://www.dojotoolkit.org/2004/dojoml";
	this.idIncrement = 0;
	
	this.getTagName = function(){return dojo.dom.getTagName.apply(dojo.dom, arguments);}
	this.getUniqueId = function(){return dojo.dom.getUniqueId.apply(dojo.dom, arguments);}
	this.getFirstChildTag = function() {return dojo.dom.getFirstChildElement.apply(dojo.dom, arguments);}
	this.getLastChildTag = function() {return dojo.dom.getLastChildElement.apply(dojo.dom, arguments);}
	this.getNextSiblingTag = function() {return dojo.dom.getNextSiblingElement.apply(dojo.dom, arguments);}
	this.getPreviousSiblingTag = function() {return dojo.dom.getPreviousSiblingElement.apply(dojo.dom, arguments);}

	this.forEachChildTag = function(node, unaryFunc) {
		var child = this.getFirstChildTag(node);
		while(child) {
			if(unaryFunc(child) == "break") { break; }
			child = this.getNextSiblingTag(child);
		}
	}

	this.moveChildren = function() {return dojo.dom.moveChildren.apply(dojo.dom, arguments);}
	this.copyChildren = function() {return dojo.dom.copyChildren.apply(dojo.dom, arguments);}
	this.clearChildren = function() {return dojo.dom.removeChildren.apply(dojo.dom, arguments);}
	this.replaceChildren = function() {return dojo.dom.replaceChildren.apply(dojo.dom, arguments);}

	this.getStyle = function() {return dojo.style.getStyle.apply(dojo.style, arguments);}
	this.toCamelCase = function() {return dojo.style.toCamelCase.apply(dojo.style, arguments);}
	this.toSelectorCase = function() {return dojo.style.toSelectorCase.apply(dojo.style, arguments);}

	this.getAncestors = function(){return dojo.dom.getAncestors.apply(dojo.dom, arguments);}
	this.isChildOf = function() {return dojo.dom.isDescendantOf.apply(dojo.dom, arguments);}
	this.createDocumentFromText = function() {return dojo.dom.createDocumentFromText.apply(dojo.dom, arguments);}

	if(dojo.render.html.capable || dojo.render.svg.capable) {
		this.createNodesFromText = function(txt, wrap){return dojo.dom.createNodesFromText.apply(dojo.dom, arguments);}
	}

	this.extractRGB = function(color) { return dojo.graphics.color.extractRGB(color); }
	this.hex2rgb = function(hex) { return dojo.graphics.color.hex2rgb(hex); }
	this.rgb2hex = function(r, g, b) { return dojo.graphics.color.rgb2hex(r, g, b); }

	this.insertBefore = function() {return dojo.dom.insertBefore.apply(dojo.dom, arguments);}
	this.before = this.insertBefore;
	this.insertAfter = function() {return dojo.dom.insertAfter.apply(dojo.dom, arguments);}
	this.after = this.insertAfter
	this.insert = function(){return dojo.dom.insertAtPosition.apply(dojo.dom, arguments);}
	this.insertAtIndex = function(){return dojo.dom.insertAtIndex.apply(dojo.dom, arguments);}
	this.textContent = function () {return dojo.dom.textContent.apply(dojo.dom, arguments);}
	this.renderedTextContent = function () {return dojo.dom.renderedTextContent.apply(dojo.dom, arguments);}
	this.remove = function (node) {return dojo.dom.removeNode.apply(dojo.dom, arguments);}
}

