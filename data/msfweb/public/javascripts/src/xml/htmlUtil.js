/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.xml.htmlUtil");
dojo.require("dojo.html");
dojo.require("dojo.style");
dojo.require("dojo.dom");

dojo.deprecated("dojo.xml.htmlUtil", "use dojo.html instead", "0.4");

dojo.xml.htmlUtil = new function(){
	this.styleSheet = dojo.style.styleSheet;
	
	this._clobberSelection = function(){return dojo.html.clearSelection.apply(dojo.html, arguments);}
	this.disableSelect = function(){return dojo.html.disableSelection.apply(dojo.html, arguments);}
	this.enableSelect = function(){return dojo.html.enableSelection.apply(dojo.html, arguments);}
	
	this.getInnerWidth = function(){return dojo.style.getInnerWidth.apply(dojo.style, arguments);}
	
	this.getOuterWidth = function(node){
		dojo.unimplemented("dojo.xml.htmlUtil.getOuterWidth");
	}

	this.getInnerHeight = function(){return dojo.style.getInnerHeight.apply(dojo.style, arguments);}

	this.getOuterHeight = function(node){
		dojo.unimplemented("dojo.xml.htmlUtil.getOuterHeight");
	}

	this.getTotalOffset = function(){return dojo.style.getTotalOffset.apply(dojo.style, arguments);}
	this.totalOffsetLeft = function(){return dojo.style.totalOffsetLeft.apply(dojo.style, arguments);}

	this.getAbsoluteX = this.totalOffsetLeft;

	this.totalOffsetTop = function(){return dojo.style.totalOffsetTop.apply(dojo.style, arguments);}
	
	this.getAbsoluteY = this.totalOffsetTop;

	this.getEventTarget = function(){return dojo.html.getEventTarget.apply(dojo.html, arguments);}
	this.getScrollTop = function() {return dojo.html.getScrollTop.apply(dojo.html, arguments);}
	this.getScrollLeft = function() {return dojo.html.getScrollLeft.apply(dojo.html, arguments);}

	this.evtTgt = this.getEventTarget;

	this.getParentOfType = function(){return dojo.html.getParentOfType.apply(dojo.html, arguments);}
	this.getAttribute = function(){return dojo.html.getAttribute.apply(dojo.html, arguments);}
	this.getAttr = function (node, attr) { // for backwards compat (may disappear!!!)
		dojo.deprecated("dojo.xml.htmlUtil.getAttr", "use dojo.xml.htmlUtil.getAttribute instead", "0.4");
		return dojo.xml.htmlUtil.getAttribute(node, attr);
	}
	this.hasAttribute = function(){return dojo.html.hasAttribute.apply(dojo.html, arguments);}

	this.hasAttr = function (node, attr) { // for backwards compat (may disappear!!!)
		dojo.deprecated("dojo.xml.htmlUtil.hasAttr", "use dojo.xml.htmlUtil.hasAttribute instead", "0.4");
		return dojo.xml.htmlUtil.hasAttribute(node, attr);
	}
	
	this.getClass = function(){return dojo.html.getClass.apply(dojo.html, arguments)}
	this.hasClass = function(){return dojo.html.hasClass.apply(dojo.html, arguments)}
	this.prependClass = function(){return dojo.html.prependClass.apply(dojo.html, arguments)}
	this.addClass = function(){return dojo.html.addClass.apply(dojo.html, arguments)}
	this.setClass = function(){return dojo.html.setClass.apply(dojo.html, arguments)}
	this.removeClass = function(){return dojo.html.removeClass.apply(dojo.html, arguments)}

	// Enum type for getElementsByClass classMatchType arg:
	this.classMatchType = {
		ContainsAll : 0, // all of the classes are part of the node's class (default)
		ContainsAny : 1, // any of the classes are part of the node's class
		IsOnly : 2 // only all of the classes are part of the node's class
	}

	this.getElementsByClass = function() {return dojo.html.getElementsByClass.apply(dojo.html, arguments)}
	this.getElementsByClassName = this.getElementsByClass;
	
	this.setOpacity = function() {return dojo.style.setOpacity.apply(dojo.style, arguments)}
	this.getOpacity = function() {return dojo.style.getOpacity.apply(dojo.style, arguments)}
	this.clearOpacity = function() {return dojo.style.clearOpacity.apply(dojo.style, arguments)}
	
	this.gravity = function(){return dojo.html.gravity.apply(dojo.html, arguments)}
	
	this.gravity.NORTH = 1;
	this.gravity.SOUTH = 1 << 1;
	this.gravity.EAST = 1 << 2;
	this.gravity.WEST = 1 << 3;
	
	this.overElement = function(){return dojo.html.overElement.apply(dojo.html, arguments)}

	this.insertCssRule = function(){return dojo.style.insertCssRule.apply(dojo.style, arguments)}
	
	this.insertCSSRule = function(selector, declaration, index){
		dojo.deprecated("dojo.xml.htmlUtil.insertCSSRule", "use dojo.style.insertCssRule instead", "0.4");
		return dojo.xml.htmlUtil.insertCssRule(selector, declaration, index);
	}
	
	this.removeCssRule = function(){return dojo.style.removeCssRule.apply(dojo.style, arguments)}

	this.removeCSSRule = function(index){
		dojo.deprecated("dojo.xml.htmlUtil.removeCSSRule", "use dojo.xml.htmlUtil.removeCssRule instead", "0.4");
		return dojo.xml.htmlUtil.removeCssRule(index);
	}

	this.insertCssFile = function(){return dojo.style.insertCssFile.apply(dojo.style, arguments)}

	this.insertCSSFile = function(URI, doc, checkDuplicates){
		dojo.deprecated("dojo.xml.htmlUtil.insertCSSFile", "use dojo.xml.htmlUtil.insertCssFile instead", "0.4");
		return dojo.xml.htmlUtil.insertCssFile(URI, doc, checkDuplicates);
	}

	this.getBackgroundColor = function() {return dojo.style.getBackgroundColor.apply(dojo.style, arguments)}

	this.getUniqueId = function() { return dojo.dom.getUniqueId(); }

	this.getStyle = function() {return dojo.style.getStyle.apply(dojo.style, arguments)}
}
