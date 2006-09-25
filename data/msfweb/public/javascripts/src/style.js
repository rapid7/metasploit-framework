/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.style");
dojo.require("dojo.graphics.color");
dojo.require("dojo.uri.Uri");
dojo.require("dojo.lang.common");

(function(){
	var h = dojo.render.html;
	var ds = dojo.style;
	var db = document["body"]||document["documentElement"];

	ds.boxSizing = {
		MARGIN_BOX: "margin-box",
		BORDER_BOX: "border-box",
		PADDING_BOX: "padding-box",
		CONTENT_BOX: "content-box"
	};
	var bs = ds.boxSizing;
	
	ds.getBoxSizing = function(node){
		if((h.ie)||(h.opera)){ 
			var cm = document["compatMode"];
			if((cm == "BackCompat")||(cm == "QuirksMode")){ 
				return bs.BORDER_BOX; 
			}else{
				return bs.CONTENT_BOX; 
			}
		}else{
			if(arguments.length == 0){ node = document.documentElement; }
			var sizing = ds.getStyle(node, "-moz-box-sizing");
			if(!sizing){ sizing = ds.getStyle(node, "box-sizing"); }
			return (sizing ? sizing : bs.CONTENT_BOX);
		}
	}

	/*

	The following several function use the dimensions shown below

		+-------------------------+
		|  margin                 |
		| +---------------------+ |
		| |  border             | |
		| | +-----------------+ | |
		| | |  padding        | | |
		| | | +-------------+ | | |
		| | | |   content   | | | |
		| | | +-------------+ | | |
		| | +-|-------------|-+ | |
		| +-|-|-------------|-|-+ |
		+-|-|-|-------------|-|-|-+
		| | | |             | | | |
		| | | |<- content ->| | | |
		| |<------ inner ------>| |
		|<-------- outer -------->|
		+-------------------------+

		* content-box

		|m|b|p|             |p|b|m|
		| |<------ offset ----->| |
		| | |<---- client --->| | |
		| | | |<-- width -->| | | |

		* border-box

		|m|b|p|             |p|b|m|
		| |<------ offset ----->| |
		| | |<---- client --->| | |
		| |<------ width ------>| |
	*/

	/*
		Notes:

		General:
			- Uncomputable values are returned as NaN.
			- setOuterWidth/Height return *false* if the outer size could not
			  be computed, otherwise *true*.
			- (sjmiles) knows no way to find the calculated values for auto-margins. 
			- All returned values are floating point in 'px' units. If a
			  non-zero computed style value is not specified in 'px', NaN is
			  returned.

		FF:
			- styles specified as '0' (unitless 0) show computed as '0pt'.

		IE:
			- clientWidth/Height are unreliable (0 unless the object has 'layout').
			- margins must be specified in px, or 0 (in any unit) for any
			  sizing function to work. Otherwise margins detect as 'auto'.
			- padding can be empty or, if specified, must be in px, or 0 (in
			  any unit) for any sizing function to work.

		Safari:
			- Safari defaults padding values to 'auto'.

		See the unit tests for examples of (un)computable values in a given browser.

	*/

	// FIXME: these work for some elements (e.g. DIV) but not others (e.g. TABLE, TEXTAREA)

	ds.isBorderBox = function(node){
		return (ds.getBoxSizing(node) == bs.BORDER_BOX);
	}

	ds.getUnitValue = function(node, cssSelector, autoIsZero){
		var s = ds.getComputedStyle(node, cssSelector);
		if((!s)||((s == 'auto')&&(autoIsZero))){ return { value: 0, units: 'px' }; }
		if(dojo.lang.isUndefined(s)){return ds.getUnitValue.bad;}
		// FIXME: is regex inefficient vs. parseInt or some manual test? 
		var match = s.match(/(\-?[\d.]+)([a-z%]*)/i);
		if (!match){return ds.getUnitValue.bad;}
		return { value: Number(match[1]), units: match[2].toLowerCase() };
	}
	// FIXME: 'bad' value should be 0?
	ds.getUnitValue.bad = { value: NaN, units: '' };
	
	ds.getPixelValue = function(node, cssSelector, autoIsZero){
		var result = ds.getUnitValue(node, cssSelector, autoIsZero);
		// FIXME: there is serious debate as to whether or not this is the right solution
		if(isNaN(result.value)){ return 0; }
		// FIXME: code exists for converting other units to px (see Dean Edward's IE7) 
		// but there are cross-browser complexities
		if((result.value)&&(result.units != 'px')){ return NaN; }
		return result.value;
	}
	
	// FIXME: deprecated
	ds.getNumericStyle = function() {
		dojo.deprecated('dojo.(style|html).getNumericStyle', 'in favor of dojo.(style|html).getPixelValue', '0.4');
		return ds.getPixelValue.apply(this, arguments); 
	}

	ds.setPositivePixelValue = function(node, selector, value){
		if(isNaN(value)){return false;}
		node.style[selector] = Math.max(0, value) + 'px'; 
		return true;
	}
	
	ds._sumPixelValues = function(node, selectors, autoIsZero){
		var total = 0;
		for(var x=0; x<selectors.length; x++){
			total += ds.getPixelValue(node, selectors[x], autoIsZero);
		}
		return total;
	}

	ds.isPositionAbsolute = function(node){
		return (ds.getComputedStyle(node, 'position') == 'absolute');
	}

	ds.getBorderExtent = function(node, side){
		return (ds.getStyle(node, 'border-' + side + '-style') == 'none' ? 0 : ds.getPixelValue(node, 'border-' + side + '-width'));
	}

	ds.getMarginWidth = function(node){
		return ds._sumPixelValues(node, ["margin-left", "margin-right"], ds.isPositionAbsolute(node));
	}

	ds.getBorderWidth = function(node){
		return ds.getBorderExtent(node, 'left') + ds.getBorderExtent(node, 'right');
	}

	ds.getPaddingWidth = function(node){
		return ds._sumPixelValues(node, ["padding-left", "padding-right"], true);
	}

	ds.getPadBorderWidth = function(node) {
		return ds.getPaddingWidth(node) + ds.getBorderWidth(node);
	}
	
	ds.getContentBoxWidth = function(node){
		node = dojo.byId(node);
		return node.offsetWidth - ds.getPadBorderWidth(node);
	}

	ds.getBorderBoxWidth = function(node){
		node = dojo.byId(node);
		return node.offsetWidth;
	}

	ds.getMarginBoxWidth = function(node){
		return ds.getInnerWidth(node) + ds.getMarginWidth(node);
	}

	ds.setContentBoxWidth = function(node, pxWidth){
		node = dojo.byId(node);
		if (ds.isBorderBox(node)){
			pxWidth += ds.getPadBorderWidth(node);
		}
		return ds.setPositivePixelValue(node, "width", pxWidth);
	}

	ds.setMarginBoxWidth = function(node, pxWidth){
		node = dojo.byId(node);
		if (!ds.isBorderBox(node)){
			pxWidth -= ds.getPadBorderWidth(node);
		}
		pxWidth -= ds.getMarginWidth(node);
		return ds.setPositivePixelValue(node, "width", pxWidth);
	}

	// FIXME: deprecate and remove
	ds.getContentWidth = ds.getContentBoxWidth;
	ds.getInnerWidth = ds.getBorderBoxWidth;
	ds.getOuterWidth = ds.getMarginBoxWidth;
	ds.setContentWidth = ds.setContentBoxWidth;
	ds.setOuterWidth = ds.setMarginBoxWidth;

	ds.getMarginHeight = function(node){
		return ds._sumPixelValues(node, ["margin-top", "margin-bottom"], ds.isPositionAbsolute(node));
	}

	ds.getBorderHeight = function(node){
		return ds.getBorderExtent(node, 'top') + ds.getBorderExtent(node, 'bottom');
	}

	ds.getPaddingHeight = function(node){
		return ds._sumPixelValues(node, ["padding-top", "padding-bottom"], true);
	}

	ds.getPadBorderHeight = function(node) {
		return ds.getPaddingHeight(node) + ds.getBorderHeight(node);
	}
	
	ds.getContentBoxHeight = function(node){
		node = dojo.byId(node);
		return node.offsetHeight - ds.getPadBorderHeight(node);
	}

	ds.getBorderBoxHeight = function(node){
		node = dojo.byId(node);
		return node.offsetHeight; // FIXME: does this work?
	}

	ds.getMarginBoxHeight = function(node){
		return ds.getInnerHeight(node) + ds.getMarginHeight(node);
	}

	ds.setContentBoxHeight = function(node, pxHeight){
		node = dojo.byId(node);
		if (ds.isBorderBox(node)){
			pxHeight += ds.getPadBorderHeight(node);
		}
		return ds.setPositivePixelValue(node, "height", pxHeight);
	}

	ds.setMarginBoxHeight = function(node, pxHeight){
		node = dojo.byId(node);
		if (!ds.isBorderBox(node)){
			pxHeight -= ds.getPadBorderHeight(node);
		}
		pxHeight -= ds.getMarginHeight(node);
		return ds.setPositivePixelValue(node, "height", pxHeight);
	}

	// FIXME: deprecate and remove
	ds.getContentHeight = ds.getContentBoxHeight;
	ds.getInnerHeight = ds.getBorderBoxHeight;
	ds.getOuterHeight = ds.getMarginBoxHeight;
	ds.setContentHeight = ds.setContentBoxHeight;
	ds.setOuterHeight = ds.setMarginBoxHeight;

	/**
	 * dojo.style.getAbsolutePosition(xyz, true) returns xyz's position relative to the document.
	 * Itells you where you would position a node
	 * inside document.body such that it was on top of xyz.  Most people set the flag to true when calling
	 * getAbsolutePosition().
	 *
	 * dojo.style.getAbsolutePosition(xyz, false) returns xyz's position relative to the viewport.
	 * It returns the position that would be returned
	 * by event.clientX/Y if the mouse were directly over the top/left of this node.
	 */
	ds.getAbsolutePosition = ds.abs = function(node, includeScroll){
		node = dojo.byId(node);
		var ret = [];
		ret.x = ret.y = 0;
		var st = dojo.html.getScrollTop();
		var sl = dojo.html.getScrollLeft();

		if(h.ie){
			with(node.getBoundingClientRect()){
				ret.x = left-2;
				ret.y = top-2;
			}
		}else if(document.getBoxObjectFor){
			// mozilla
			var bo = document.getBoxObjectFor(node);
			ret.x = bo.x - ds.sumAncestorProperties(node, "scrollLeft");
			ret.y = bo.y - ds.sumAncestorProperties(node, "scrollTop");
		}else{
			if(node["offsetParent"]){
				var endNode;		
				// in Safari, if the node is an absolutely positioned child of
				// the body and the body has a margin the offset of the child
				// and the body contain the body's margins, so we need to end
				// at the body
				if(	(h.safari)&&
					(node.style.getPropertyValue("position") == "absolute")&&
					(node.parentNode == db)){
					endNode = db;
				}else{
					endNode = db.parentNode;
				}

				if(node.parentNode != db){
					var nd = node;
					if(window.opera){ nd = db; }
					ret.x -= ds.sumAncestorProperties(nd, "scrollLeft");
					ret.y -= ds.sumAncestorProperties(nd, "scrollTop");
				}
				do{
					var n = node["offsetLeft"];
					ret.x += isNaN(n) ? 0 : n;
					var m = node["offsetTop"];
					ret.y += isNaN(m) ? 0 : m;
					node = node.offsetParent;
				}while((node != endNode)&&(node != null));
			}else if(node["x"]&&node["y"]){
				ret.x += isNaN(node.x) ? 0 : node.x;
				ret.y += isNaN(node.y) ? 0 : node.y;
			}
		}

		// account for document scrolling!
		if(includeScroll){
			ret.y += st;
			ret.x += sl;
		}

		ret[0] = ret.x;
		ret[1] = ret.y;
		return ret;
	}

	ds.sumAncestorProperties = function(node, prop){
		node = dojo.byId(node);
		if(!node){ return 0; } // FIXME: throw an error?
		
		var retVal = 0;
		while(node){
			var val = node[prop];
			if(val){
				retVal += val - 0;
				if(node==document.body){ break; }// opera and khtml #body & #html has the same values, we only need one value
			}
			node = node.parentNode;
		}
		return retVal;
	}

	ds.getTotalOffset = function(node, type, includeScroll){
		return ds.abs(node, includeScroll)[(type == "top") ? "y" : "x"];
	}

	ds.getAbsoluteX = ds.totalOffsetLeft = function(node, includeScroll){
		return ds.getTotalOffset(node, "left", includeScroll);
	}

	ds.getAbsoluteY = ds.totalOffsetTop = function(node, includeScroll){
		return ds.getTotalOffset(node, "top", includeScroll);
	}

	ds.styleSheet = null;

	// FIXME: this is a really basic stub for adding and removing cssRules, but
	// it assumes that you know the index of the cssRule that you want to add 
	// or remove, making it less than useful.  So we need something that can 
	// search for the selector that you you want to remove.
	ds.insertCssRule = function(selector, declaration, index) {
		if (!ds.styleSheet) {
			if (document.createStyleSheet) { // IE
				ds.styleSheet = document.createStyleSheet();
			} else if (document.styleSheets[0]) { // rest
				// FIXME: should create a new style sheet here
				// fall back on an exsiting style sheet
				ds.styleSheet = document.styleSheets[0];
			} else { return null; } // fail
		}

		if (arguments.length < 3) { // index may == 0
			if (ds.styleSheet.cssRules) { // W3
				index = ds.styleSheet.cssRules.length;
			} else if (ds.styleSheet.rules) { // IE
				index = ds.styleSheet.rules.length;
			} else { return null; } // fail
		}

		if (ds.styleSheet.insertRule) { // W3
			var rule = selector + " { " + declaration + " }";
			return ds.styleSheet.insertRule(rule, index);
		} else if (ds.styleSheet.addRule) { // IE
			return ds.styleSheet.addRule(selector, declaration, index);
		} else { return null; } // fail
	}

	ds.removeCssRule = function(index){
		if(!ds.styleSheet){
			dojo.debug("no stylesheet defined for removing rules");
			return false;
		}
		if(h.ie){
			if(!index){
				index = ds.styleSheet.rules.length;
				ds.styleSheet.removeRule(index);
			}
		}else if(document.styleSheets[0]){
			if(!index){
				index = ds.styleSheet.cssRules.length;
			}
			ds.styleSheet.deleteRule(index);
		}
		return true;
	}

	// calls css by XmlHTTP and inserts it into DOM as <style [widgetType="widgetType"]> *downloaded cssText*</style>
	ds.insertCssFile = function(URI, doc, checkDuplicates){
		if(!URI){ return; }
		if(!doc){ doc = document; }
		var cssStr = dojo.hostenv.getText(URI);
		cssStr = ds.fixPathsInCssText(cssStr, URI);

		if(checkDuplicates){
			var styles = doc.getElementsByTagName("style");
			var cssText = "";
			for(var i = 0; i<styles.length; i++){
				cssText = (styles[i].styleSheet && styles[i].styleSheet.cssText) ? styles[i].styleSheet.cssText : styles[i].innerHTML;
				if(cssStr == cssText){ return; }
			}
		}

		var style = ds.insertCssText(cssStr);
		// insert custom attribute ex dbgHref="../foo.css" usefull when debugging in DOM inspectors, no?
		if(style && djConfig.isDebug){
			style.setAttribute("dbgHref", URI);
		}
		return style
	}

	// DomNode Style  = insertCssText(String ".dojoMenu {color: green;}"[, DomDoc document, dojo.uri.Uri Url ])
	ds.insertCssText = function(cssStr, doc, URI){
		if(!cssStr){ return; }
		if(!doc){ doc = document; }
		if(URI){// fix paths in cssStr
			cssStr = ds.fixPathsInCssText(cssStr, URI);
		}
		var style = doc.createElement("style");
		style.setAttribute("type", "text/css");
		// IE is b0rken enough to require that we add the element to the doc
		// before changing it's properties
		var head = doc.getElementsByTagName("head")[0];
		if(!head){ // must have a head tag 
			dojo.debug("No head tag in document, aborting styles");
			return;
		}else{
			head.appendChild(style);
		}
		if(style.styleSheet){// IE
			style.styleSheet.cssText = cssStr;
		}else{ // w3c
			var cssText = doc.createTextNode(cssStr);
			style.appendChild(cssText);
		}
		return style;
	}

	// String cssText = fixPathsInCssText(String cssStr, dojo.uri.Uri URI)
	// usage: cssText comes from dojoroot/src/widget/templates/HtmlFoobar.css
	// 	it has .dojoFoo { background-image: url(images/bar.png);} 
	//	then uri should point to dojoroot/src/widget/templates/
	ds.fixPathsInCssText = function(cssStr, URI){
		if(!cssStr || !URI){ return; }
		var pos = 0; var str = ""; var url = "";
		while(pos!=-1){
			pos = 0;url = "";
			pos = cssStr.indexOf("url(", pos);
			if(pos<0){ break; }
			str += cssStr.slice(0,pos+4);
			cssStr = cssStr.substring(pos+4, cssStr.length);
			url += cssStr.match(/^[\t\s\w()\/.\\'"-:#=&?]*\)/)[0]; // url string
			cssStr = cssStr.substring(url.length-1, cssStr.length); // remove url from css string til next loop
			url = url.replace(/^[\s\t]*(['"]?)([\w()\/.\\'"-:#=&?]*)\1[\s\t]*?\)/,"$2"); // clean string
			if(url.search(/(file|https?|ftps?):\/\//)==-1){
				url = (new dojo.uri.Uri(URI,url).toString());
			}
			str += url;
		};
		return str+cssStr;
	}

	ds.getBackgroundColor = function(node) {
		node = dojo.byId(node);
		var color;
		do{
			color = ds.getStyle(node, "background-color");
			// Safari doesn't say "transparent"
			if(color.toLowerCase() == "rgba(0, 0, 0, 0)") { color = "transparent"; }
			if(node == document.getElementsByTagName("body")[0]) { node = null; break; }
			node = node.parentNode;
		}while(node && dojo.lang.inArray(color, ["transparent", ""]));
		if(color == "transparent"){
			color = [255, 255, 255, 0];
		}else{
			color = dojo.graphics.color.extractRGB(color);
		}
		return color;
	}

	ds.getComputedStyle = function(node, cssSelector, inValue){
		node = dojo.byId(node);
		// cssSelector may actually be in camel case, so force selector version
		var cssSelector = ds.toSelectorCase(cssSelector);
		var property = ds.toCamelCase(cssSelector);
		if(!node || !node.style){
			return inValue;
		}else if(document.defaultView){ // W3, gecko, KHTML
			try{			
				var cs = document.defaultView.getComputedStyle(node, "");
				if (cs){ 
					return cs.getPropertyValue(cssSelector);
				} 
			}catch(e){ // reports are that Safari can throw an exception above
				if (node.style.getPropertyValue){ // W3
					return node.style.getPropertyValue(cssSelector);
				}else return inValue;
			}
		}else if(node.currentStyle){ // IE
			return node.currentStyle[property];
		}if(node.style.getPropertyValue){ // W3
			return node.style.getPropertyValue(cssSelector);
		}else{
			return inValue;
		}
	}

	/** 
	 * Retrieve a property value from a node's style object.
	 */
	ds.getStyleProperty = function(node, cssSelector){
		node = dojo.byId(node);
		// FIXME: should we use node.style.getPropertyValue over style[property]?
		// style[property] works in all (modern) browsers, getPropertyValue is W3 but not supported in IE
		// FIXME: what about runtimeStyle?
		return (node && node.style ? node.style[ds.toCamelCase(cssSelector)] : undefined);
	}

	/** 
	 * Retrieve a property value from a node's style object.
	 */
	ds.getStyle = function(node, cssSelector){
		var value = ds.getStyleProperty(node, cssSelector);
		return (value ? value : ds.getComputedStyle(node, cssSelector));
	}

	ds.setStyle = function(node, cssSelector, value){
		node = dojo.byId(node);
		if(node && node.style){
			var camelCased = ds.toCamelCase(cssSelector);
			node.style[camelCased] = value;
		}
	}

	ds.toCamelCase = function(selector) {
		var arr = selector.split('-'), cc = arr[0];
		for(var i = 1; i < arr.length; i++) {
			cc += arr[i].charAt(0).toUpperCase() + arr[i].substring(1);
		}
		return cc;		
	}

	ds.toSelectorCase = function(selector) {
		return selector.replace(/([A-Z])/g, "-$1" ).toLowerCase() ;
	}

	/* float between 0.0 (transparent) and 1.0 (opaque) */
	ds.setOpacity = function setOpacity(node, opacity, dontFixOpacity) {
		node = dojo.byId(node);
		if(!dontFixOpacity){
			if( opacity >= 1.0){
				if(h.ie){
					ds.clearOpacity(node);
					return;
				}else{
					opacity = 0.999999;
				}
			}else if( opacity < 0.0){ opacity = 0; }
		}
		if(h.ie){
			if(node.nodeName.toLowerCase() == "tr"){
				// FIXME: is this too naive? will we get more than we want?
				var tds = node.getElementsByTagName("td");
				for(var x=0; x<tds.length; x++){
					tds[x].style.filter = "Alpha(Opacity="+opacity*100+")";
				}
			}
			node.style.filter = "Alpha(Opacity="+opacity*100+")";
		}else if(h.moz){
			node.style.opacity = opacity; // ffox 1.0 directly supports "opacity"
			node.style.MozOpacity = opacity;
		}else if(h.safari){
			node.style.opacity = opacity; // 1.3 directly supports "opacity"
			node.style.KhtmlOpacity = opacity;
		}else{
			node.style.opacity = opacity;
		}
	}
		
	ds.getOpacity = function getOpacity (node){
		node = dojo.byId(node);
		if(h.ie){
			var opac = (node.filters && node.filters.alpha &&
				typeof node.filters.alpha.opacity == "number"
				? node.filters.alpha.opacity : 100) / 100;
		}else{
			var opac = node.style.opacity || node.style.MozOpacity ||
				node.style.KhtmlOpacity || 1;
		}
		return opac >= 0.999999 ? 1.0 : Number(opac);
	}

	ds.clearOpacity = function clearOpacity(node){
		node = dojo.byId(node);
		var ns = node.style;
		if(h.ie){
			try {
				if( node.filters && node.filters.alpha ){
					ns.filter = ""; // FIXME: may get rid of other filter effects
				}
			} catch(e) {
				/*
				 * IE7 gives error if node.filters not set;
				 * don't know why or how to workaround (other than this)
				 */
			}
		}else if(h.moz){
			ns.opacity = 1;
			ns.MozOpacity = 1;
		}else if(h.safari){
			ns.opacity = 1;
			ns.KhtmlOpacity = 1;
		}else{
			ns.opacity = 1;
		}
	}

	/** 
	* Set the given style attributes for the node. 
	* Patch submitted by Wolfram Kriesing, 22/03/2006.
	*
	* Ie. dojo.style.setStyleAttributes(myNode, "position:absolute; left:10px; top:10px;") 
	* This just makes it easier to set a style directly without the need to  
	* override it completely (as node.setAttribute() would). 
	* If there is a dojo-method for an attribute, like for "opacity" there 
	* is setOpacity, the dojo method is called instead. 
	* For example: dojo.style.setStyleAttributes(myNode, "opacity: .4"); 
	*  
	* Additionally all the dojo.style.set* methods can also be used. 
	* Ie. when attributes contains "outer-height: 10;" it will call dojo.style.setOuterHeight("10"); 
	* 
	* @param object The node to set the style attributes for. 
	* @param string Ie. "position:absolute; left:10px; top:10px;" 
	*/ 
	ds.setStyleAttributes = function(node, attributes) { 
		var methodMap={ 
			"opacity":dojo.style.setOpacity,
			"content-height":dojo.style.setContentHeight,
			"content-width":dojo.style.setContentWidth,
			"outer-height":dojo.style.setOuterHeight,
			"outer-width":dojo.style.setOuterWidth 
		} 

		var splittedAttribs=attributes.replace(/(;)?\s*$/, "").split(";"); 
		for(var i=0; i<splittedAttribs.length; i++){ 
			var nameValue=splittedAttribs[i].split(":"); 
			var name=nameValue[0].replace(/\s*$/, "").replace(/^\s*/, "").toLowerCase();
			var value=nameValue[1].replace(/\s*$/, "").replace(/^\s*/, "");
			if(dojo.lang.has(methodMap,name)) { 
				methodMap[name](node,value); 
			} else { 
				node.style[dojo.style.toCamelCase(name)]=value; 
			} 
		} 
	} 

	ds._toggle = function(node, tester, setter){
		node = dojo.byId(node);
		setter(node, !tester(node));
		return tester(node);
	}

	// show/hide are library constructs

	// show() 
	// if the node.style.display == 'none' then 
	// set style.display to '' or the value cached by hide()
	ds.show = function(node){
		node = dojo.byId(node);
		if(ds.getStyleProperty(node, 'display')=='none'){
			ds.setStyle(node, 'display', (node.dojoDisplayCache||''));
			node.dojoDisplayCache = undefined;	// cannot use delete on a node in IE6
		}
	}

	// if the node.style.display == 'none' then 
	// set style.display to '' or the value cached by hide()
	ds.hide = function(node){
		node = dojo.byId(node);
		if(typeof node["dojoDisplayCache"] == "undefined"){ // it could == '', so we cannot say !node.dojoDisplayCount
			var d = ds.getStyleProperty(node, 'display')
			if(d!='none'){
				node.dojoDisplayCache = d;
			}
		}
		ds.setStyle(node, 'display', 'none');
	}

	// setShowing() calls show() if showing is true, hide() otherwise
	ds.setShowing = function(node, showing){
		ds[(showing ? 'show' : 'hide')](node);
	}

	// isShowing() is true if the node.style.display is not 'none'
	// FIXME: returns true if node is bad, isHidden would be easier to make correct
	ds.isShowing = function(node){
		return (ds.getStyleProperty(node, 'display') != 'none');
	}

	// Call setShowing() on node with the complement of isShowing(), then return the new value of isShowing()
	ds.toggleShowing = function(node){
		return ds._toggle(node, ds.isShowing, ds.setShowing);
	}

	// display is a CSS concept

	// Simple mapping of tag names to display values
	// FIXME: simplistic 
	ds.displayMap = { tr: '', td: '', th: '', img: 'inline', span: 'inline', input: 'inline', button: 'inline' };

	// Suggest a value for the display property that will show 'node' based on it's tag
	ds.suggestDisplayByTagName = function(node)
	{
		node = dojo.byId(node);
		if(node && node.tagName){
			var tag = node.tagName.toLowerCase();
			return (tag in ds.displayMap ? ds.displayMap[tag] : 'block');
		}
	}

	// setDisplay() sets the value of style.display to value of 'display' parameter if it is a string.
	// Otherwise, if 'display' is false, set style.display to 'none'.
	// Finally, set 'display' to a suggested display value based on the node's tag
	ds.setDisplay = function(node, display){
		ds.setStyle(node, 'display', (dojo.lang.isString(display) ? display : (display ? ds.suggestDisplayByTagName(node) : 'none')));
	}

	// isDisplayed() is true if the the computed display style for node is not 'none'
	// FIXME: returns true if node is bad, isNotDisplayed would be easier to make correct
	ds.isDisplayed = function(node){
		return (ds.getComputedStyle(node, 'display') != 'none');
	}

	// Call setDisplay() on node with the complement of isDisplayed(), then
	// return the new value of isDisplayed()
	ds.toggleDisplay = function(node){
		return ds._toggle(node, ds.isDisplayed, ds.setDisplay);
	}

	// visibility is a CSS concept

	// setVisibility() sets the value of style.visibility to value of
	// 'visibility' parameter if it is a string.
	// Otherwise, if 'visibility' is false, set style.visibility to 'hidden'.
	// Finally, set style.visibility to 'visible'.
	ds.setVisibility = function(node, visibility){
		ds.setStyle(node, 'visibility', (dojo.lang.isString(visibility) ? visibility : (visibility ? 'visible' : 'hidden')));
	}

	// isVisible() is true if the the computed visibility style for node is not 'hidden'
	// FIXME: returns true if node is bad, isInvisible would be easier to make correct
	ds.isVisible = function(node){
		return (ds.getComputedStyle(node, 'visibility') != 'hidden');
	}

	// Call setVisibility() on node with the complement of isVisible(), then
	// return the new value of isVisible()
	ds.toggleVisibility = function(node){
		return ds._toggle(node, ds.isVisible, ds.setVisibility);
	}

	// in: coordinate array [x,y,w,h] or dom node
	// return: coordinate array
	ds.toCoordinateArray = function(coords, includeScroll) {
		if(dojo.lang.isArray(coords)){
			// coords is already an array (of format [x,y,w,h]), just return it
			while ( coords.length < 4 ) { coords.push(0); }
			while ( coords.length > 4 ) { coords.pop(); }
			var ret = coords;
		} else {
			// coords is an dom object (or dom object id); return it's coordinates
			var node = dojo.byId(coords);
			var pos = ds.getAbsolutePosition(node, includeScroll);
			var ret = [
				pos.x,
				pos.y,
				ds.getBorderBoxWidth(node),
				ds.getBorderBoxHeight(node)
			];
		}
		ret.x = ret[0];
		ret.y = ret[1];
		ret.w = ret[2];
		ret.h = ret[3];
		return ret;
	};
})();
