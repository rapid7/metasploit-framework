/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.HtmlWidget");
dojo.require("dojo.widget.DomWidget");
dojo.require("dojo.html");
dojo.require("dojo.html.extras");
dojo.require("dojo.lang.extras");
dojo.require("dojo.lang.func");
dojo.require("dojo.lfx.toggle");

dojo.declare("dojo.widget.HtmlWidget", dojo.widget.DomWidget, {								 
	widgetType: "HtmlWidget",

	templateCssPath: null,
	templatePath: null,

	// for displaying/hiding widget
	toggle: "plain",
	toggleDuration: 150,

	animationInProgress: false,

	initialize: function(args, frag){
	},

	postMixInProperties: function(args, frag){
		// now that we know the setting for toggle, get toggle object
		// (default to plain toggler if user specified toggler not present)
		this.toggleObj =
			dojo.lfx.toggle[this.toggle.toLowerCase()] || dojo.lfx.toggle.plain;
	},

	getContainerHeight: function(){
		// NOTE: container height must be returned as the INNER height
		dojo.unimplemented("dojo.widget.HtmlWidget.getContainerHeight");
	},

	getContainerWidth: function(){
		return this.parent.domNode.offsetWidth;
	},

	setNativeHeight: function(height){
		var ch = this.getContainerHeight();
	},

	createNodesFromText: function(txt, wrap){
		return dojo.html.createNodesFromText(txt, wrap);
	},

	destroyRendering: function(finalize){
		try{
			if(!finalize){
				dojo.event.browser.clean(this.domNode);
			}
			this.domNode.parentNode.removeChild(this.domNode);
			delete this.domNode;
		}catch(e){ /* squelch! */ }
	},

	/////////////////////////////////////////////////////////
	// Displaying/hiding the widget
	/////////////////////////////////////////////////////////
	isShowing: function(){
		return dojo.style.isShowing(this.domNode);
	},

	toggleShowing: function(){
		// dojo.style.toggleShowing(this.domNode);
		if(this.isHidden){
			this.show();
		}else{
			this.hide();
		}
	},

	show: function(){
		this.animationInProgress=true;
		this.isHidden = false;
		this.toggleObj.show(this.domNode, this.toggleDuration, null,
			dojo.lang.hitch(this, this.onShow), this.explodeSrc);
	},

	// called after the show() animation has completed
	onShow: function(){
		this.animationInProgress=false;
		this.checkSize();
	},

	hide: function(){
		this.animationInProgress = true;
		this.isHidden = true;
		this.toggleObj.hide(this.domNode, this.toggleDuration, null,
			dojo.lang.hitch(this, this.onHide), this.explodeSrc);
	},

	// called after the hide() animation has completed
	onHide: function(){
		this.animationInProgress=false;
	},

	//////////////////////////////////////////////////////////////////////////////
	// Sizing related methods
	//  If the parent changes size then for each child it should call either
	//   - resizeTo(): size the child explicitly
	//   - or checkSize(): notify the child the the parent has changed size
	//////////////////////////////////////////////////////////////////////////////

	// Test if my size has changed.
	// If width & height are specified then that's my new size; otherwise,
	// query outerWidth/outerHeight of my domNode
	_isResized: function(w, h){
		// If I'm not being displayed then disregard (show() must
		// check if the size has changed)
		if(!this.isShowing()){ return false; }

		// If my parent has been resized and I have style="height: 100%"
		// or something similar then my size has changed too.
		w=w||dojo.style.getOuterWidth(this.domNode);
		h=h||dojo.style.getOuterHeight(this.domNode);
		if(this.width == w && this.height == h){ return false; }

		this.width=w;
		this.height=h;
		return true;
	},

	// Called when my parent has changed size, but my parent won't call resizeTo().
	// This is useful if my size is height:100% or something similar.
	// Also called whenever I am shown, because the first time I am shown I may need
	// to do size calculations.
	checkSize: function(){
		if(!this._isResized()){ return; }
		this.onResized();
	},

	// Explicitly set this widget's size (in pixels).
	resizeTo: function(w, h){
		if(!this._isResized(w,h)){ return; }
		dojo.style.setOuterWidth(this.domNode, w);
		dojo.style.setOuterHeight(this.domNode, h);
		this.onResized();
	},

	resizeSoon: function(){
		if(this.isShowing()){
			dojo.lang.setTimeout(this, this.onResized, 0);
		}
	},

	// Called when my size has changed.
	// Must notify children if their size has (possibly) changed
	onResized: function(){
		dojo.lang.forEach(this.children, function(child){ child.checkSize(); });
	}
});
