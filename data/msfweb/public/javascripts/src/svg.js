/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.svg");
dojo.require("dojo.lang");
dojo.require("dojo.dom");

dojo.lang.mixin(dojo.svg, dojo.dom);

dojo.svg.graphics=dojo.svg.g=new function(/* DomDocument */ d){
	//	summary
	//	Singleton to encapsulate SVG rendering functions.
	this.suspend=function(){
		//	summary
		//	Suspend the rendering engine
		try { d.documentElement.suspendRedraw(0); } catch(e){ }
	};
	this.resume=function(){
		//	summary
		//	Resume the rendering engine
		try { d.documentElement.unsuspendRedraw(0); } catch(e){ }
	};
	this.force=function(){
		//	summary
		//	Force the render engine to redraw
		try { d.documentElement.forceRedraw(); } catch(e){ }
	};
}(document);

dojo.svg.animations=dojo.svg.anim=new function(/* DOMDocument */ d){
	//	summary
	//	Singleton to encapsulate SVG animation functionality.
	this.arePaused=function(){
		//	summary
		//	check to see if all animations are paused
		try {
			return d.documentElement.animationsPaused();	//	bool
		} catch(e){
			return false;	//	bool
		}
	} ;
	this.pause=function(){
		//	summary
		//	pause all animations
		try { d.documentElement.pauseAnimations(); } catch(e){ }
	};
	this.resume=function(){
		//	summary
		//	resume all animations
		try { d.documentElement.unpauseAnimations(); } catch(e){ }
	};
}(document);

//	fixme: these functions should be mixed in from dojo.style, but dojo.style is HTML-centric and needs to change.
dojo.svg.toCamelCase=function(/* string */ selector){
	//	summary
	//	converts a CSS-style selector to a camelCased one
	var arr=selector.split('-'), cc=arr[0];
	for(var i=1; i < arr.length; i++) {
		cc += arr[i].charAt(0).toUpperCase() + arr[i].substring(1);
	}
	return cc;	// string
};
dojo.svg.toSelectorCase=function(/* string */ selector) {
	//	summary
	//	converts a camelCased selector to a CSS style one
	return selector.replace(/([A-Z])/g, "-$1" ).toLowerCase();	//	string
};
dojo.svg.getStyle=function(/* SVGElement */ node, /* string */ cssSelector){
	//	summary
	//	get the computed style of selector for node.
	return document.defaultView.getComputedStyle(node, cssSelector);	//	object
};
dojo.svg.getNumericStyle=function(/* SVGElement */ node, /* string */ cssSelector){
	//	summary
	//	return the numeric version of the computed style of selector on node.
	return parseFloat(dojo.svg.getStyle(node, cssSelector));
};

//	fixme: there are different ways of doing the following, need to take into account
dojo.svg.getOpacity=function(/* SVGElement */node){
	//	summary
	//	Return the opacity of the passed element
	return Math.min(1.0, dojo.svg.getNumericStyle(node, "fill-opacity"));	//	float
};
dojo.svg.setOpacity=function(/* SVGElement */ node, /* float */ opacity){
	//	summary
	//	set the opacity of node using attributes.
	node.setAttributeNS(this.xmlns.svg, "fill-opacity", opacity);
	node.setAttributeNS(this.xmlns.svg, "stroke-opacity", opacity);
};
dojo.svg.clearOpacity=function(/* SVGElement */ node){
	//	summary
	//	Set any attributes setting opacity to opaque (1.0)
	node.setAttributeNS(this.xmlns.svg, "fill-opacity", "1.0");
	node.setAttributeNS(this.xmlns.svg, "stroke-opacity", "1.0");
};

/**
 *	Coordinates and dimensions.
 */

// TODO ////////////////////////////////////////////////////////// TODO
dojo.svg.getCoords=function(/* SVGElement */ node){
	if (node.getBBox) {
		var box=node.getBBox();
		return { x: box.x, y: box.y };
	}
	return null;
};
dojo.svg.setCoords=function(node, coords){
	var p=dojo.svg.getCoords();
	if (!p) return;
	var dx=p.x - coords.x;
	var dy=p.y - coords.y;
	dojo.svg.translate(node, dx, dy);
};
dojo.svg.getDimensions=function(node){
	if (node.getBBox){
		var box=node.getBBox();
		return { width: box.width, height : box.height };
	}
	return null;
};
dojo.svg.setDimensions=function(node, dim){
	//	will only support shape-based and container elements; path-based elements are ignored.
	if (node.width){
		node.width.baseVal.value=dim.width;
		node.height.baseVal.value=dim.height;
	}
	else if (node.r){
		node.r.baseVal.value=Math.min(dim.width, dim.height)/2;
	}
	else if (node.rx){
		node.rx.baseVal.value=dim.width/2;
		node.ry.baseVal.value=dim.height/2;
	}
};

/**
 *	Transformations.
 */
dojo.svg.translate=function(node, dx, dy){
	if (node.transform && node.ownerSVGElement && node.ownerSVGElement.createSVGTransform){
		var t=node.ownerSVGElement.createSVGTransform();
		t.setTranslate(dx, dy);
		node.transform.baseVal.appendItem(t);
	}
};
dojo.svg.scale=function(node, scaleX, scaleY){
	if (!scaleY) var scaleY=scaleX;
	if (node.transform && node.ownerSVGElement && node.ownerSVGElement.createSVGTransform){
		var t=node.ownerSVGElement.createSVGTransform();
		t.setScale(scaleX, scaleY);
		node.transform.baseVal.appendItem(t);
	}
};
dojo.svg.rotate=function(node, ang, cx, cy){
	if (node.transform && node.ownerSVGElement && node.ownerSVGElement.createSVGTransform){
		var t=node.ownerSVGElement.createSVGTransform();
		if (!cx) t.setMatrix(t.matrix.rotate(ang));
		else t.setRotate(ang, cx, cy);
		node.transform.baseVal.appendItem(t);
	}
};
dojo.svg.skew=function(node, ang, axis){
	var dir=axis || "x";
	if (node.transform && node.ownerSVGElement && node.ownerSVGElement.createSVGTransform){
		var t=node.ownerSVGElement.createSVGTransform();
		if (dir != "x") t.setSkewY(ang);
		else t.setSkewX(ang);
		node.transform.baseVal.appendItem(t);
	}
};
dojo.svg.flip=function(node, axis){
	var dir=axis || "x";
	if (node.transform && node.ownerSVGElement && node.ownerSVGElement.createSVGTransform){
		var t=node.ownerSVGElement.createSVGTransform();
		t.setMatrix((dir != "x") ? t.matrix.flipY() : t.matrix.flipX());
		node.transform.baseVal.appendItem(t);
	}
};
dojo.svg.invert=function(node){
	if (node.transform && node.ownerSVGElement && node.ownerSVGElement.createSVGTransform){
		var t=node.ownerSVGElement.createSVGTransform();
		t.setMatrix(t.matrix.inverse());
		node.transform.baseVal.appendItem(t);
	}
};
dojo.svg.applyMatrix=function(node, a, b, c, d, e, f){
	if (node.transform && node.ownerSVGElement && node.ownerSVGElement.createSVGTransform){
		var m;
		if (b){
			var m=node.ownerSVGElement.createSVGMatrix();
			m.a=a;
			m.b=b;
			m.c=c;
			m.d=d;
			m.e=e;
			m.f=f;
		} else m=a;
		var t=node.ownerSVGElement.createSVGTransform();
		t.setMatrix(m);
		node.transform.baseVal.appendItem(t);
	}
};

/**
 *	Grouping and z-index operations.
 */
dojo.svg.group=function(nodes){
	//	expect an array of nodes, attaches the group to the parent of the first node.
	var p=nodes.item(0).parentNode;
	var g=document.createElementNS(this.xmlns.svg, "g");
	for (var i=0; i < nodes.length; i++) g.appendChild(nodes.item(i));
	p.appendChild(g);
	return g;
};
dojo.svg.ungroup=function(g){
	//	puts the children of the group on the same level as group was.
	var p=g.parentNode;
	while (g.childNodes.length > 0) p.appendChild(g.childNodes.item(0));
	p.removeChild(g);
};
//	if the node is part of a group, return the group, else return null.
dojo.svg.getGroup=function(node){
	//	if the node is part of a group, return the group, else return null.
	var a=this.getAncestors(node);
	for (var i=0; i < a.length; i++){
		if (a[i].nodeType == this.ELEMENT_NODE && a[i].nodeName.toLowerCase() == "g")
			return a[i];
	}
	return null;
};
dojo.svg.bringToFront=function(node){
	var n=this.getGroup(node) || node;
	n.ownerSVGElement.appendChild(n);
};
dojo.svg.sendToBack=function(node){
	var n=this.getGroup(node) || node;
	n.ownerSVGElement.insertBefore(n, n.ownerSVGElement.firstChild);
};

//	TODO: possibly push node up a level in the DOM if it's at the beginning or end of the childNodes list.
dojo.svg.bringForward=function(node){
	var n=this.getGroup(node) || node;
	if (this.getLastChildElement(n.parentNode) != n){
		this.insertAfter(n, this.getNextSiblingElement(n), true);
	}
};
dojo.svg.sendBackward=function(node){
	var n=this.getGroup(node) || node;
	if (this.getFirstChildElement(n.parentNode) != n){
		this.insertBefore(n, this.getPreviousSiblingElement(n), true);
	}
};
// END TODO ////////////////////////////////////////////////////// TODO

dojo.svg.createNodesFromText=function(/* string */ txt, /* bool? */ wrap){
	//	summary
	//	Create a list of nodes from text
	var docFrag=(new DOMParser()).parseFromString(txt, "text/xml").normalize();
	if(wrap){ 
		return [docFrag.firstChild.cloneNode(true)];	//	array
	}
	var nodes=[];
	for(var x=0; x<docFrag.childNodes.length; x++){
		nodes.push(docFrag.childNodes.item(x).cloneNode(true));
	}
	return nodes;	// array
}
// vim:ts=4:noet:tw=0:
