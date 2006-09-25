/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.Tooltip");
dojo.require("dojo.widget.html.ContentPane");
dojo.require("dojo.widget.Tooltip");
dojo.require("dojo.uri");
dojo.require("dojo.widget.*");
dojo.require("dojo.event");
dojo.require("dojo.style");
dojo.require("dojo.html");

dojo.widget.defineWidget(
	"dojo.widget.html.Tooltip",
	dojo.widget.html.ContentPane,
	{
		widgetType: "Tooltip",
		isContainer: true,
	
		// Constructor arguments
		caption: "",
		showDelay: 500,
		hideDelay: 100,
		connectId: "",
	
		templatePath: dojo.uri.dojoUri("src/widget/templates/HtmlTooltipTemplate.html"),
		templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlTooltipTemplate.css"),
	
		connectNode: null,
	
		// Tooltip has the following possible states:
		//   erased - nothing on screen
		//   displaying - currently being faded in (partially displayed)
		//   displayed - fully displayed
		//   erasing - currently being faded out (partially erased)
		state: "erased",
	
		fillInTemplate: function(args, frag){
			if(this.caption != ""){
				this.domNode.appendChild(document.createTextNode(this.caption));
			}
			this.connectNode = dojo.byId(this.connectId);		
			dojo.widget.html.Tooltip.superclass.fillInTemplate.call(this, args, frag);
		},
		
		postCreate: function(args, frag){
			// The domnode was appended to my parent widget's domnode, but the positioning
			// only works if the domnode is a child of document.body
			document.body.appendChild(this.domNode);
	
			dojo.event.connect(this.connectNode, "onmouseover", this, "onMouseOver");
			dojo.widget.html.Tooltip.superclass.postCreate.call(this, args, frag);
		},
		
		onMouseOver: function(e) {
			this.mouse = {x: e.pageX, y: e.pageY};
	
			if(!this.showTimer){
				this.showTimer = setTimeout(dojo.lang.hitch(this, "show"), this.showDelay);
				dojo.event.connect(document.documentElement, "onmousemove", this, "onMouseMove");
			}
		},
	
		onMouseMove: function(e) {
			this.mouse = {x: e.pageX, y: e.pageY};
	
			if(dojo.html.overElement(this.connectNode, e) || dojo.html.overElement(this.domNode, e)) {
				// If the tooltip has been scheduled to be erased, cancel that timer
				// since we are hovering over element/tooltip again
				if(this.hideTimer) {
					clearTimeout(this.hideTimer);
					delete this.hideTimer;
				}
			} else {
				// mouse has been moved off the element/tooltip
				// note: can't use onMouseOut to detect this because the "explode" effect causes
				// spurious onMouseOut/onMouseOver events (due to interference from outline)
				if(this.showTimer){
					clearTimeout(this.showTimer);
					delete this.showTimer;
				}
				if((this.state=="displaying"||this.state=="displayed") && !this.hideTimer){
					this.hideTimer = setTimeout(dojo.lang.hitch(this, "hide"), this.hideDelay);
				}
			}
		},
	
		show: function() {
			if(this.state=="erasing"){
				// we are in the process of erasing; when that is finished, display it.
				this.displayScheduled=true;
				return;
			}
			if ( this.state=="displaying" || this.state=="displayed" ) { return; }
	
			// prevent IE bleed through (iframe creation is deferred until first show()
			// call because apparently it takes a long time)
			if(!this.bgIframe){
				this.bgIframe = new dojo.html.BackgroundIframe(this.domNode);
			}
	
			this.position();
	
			// if rendering using explosion effect, need to set explosion source
			this.explodeSrc = [this.mouse.x, this.mouse.y];
	
			this.state="displaying";
	
			dojo.widget.html.Tooltip.superclass.show.call(this);
		},
	
		onShow: function() {
			dojo.widget.html.Tooltip.superclass.onShow.call(this);
			
			this.state="displayed";
			
			// in the corner case where the user has moved his mouse away
			// while the tip was fading in
			if(this.eraseScheduled){
				this.hide();
				this.eraseScheduled=false;
			}
		},
	
		hide: function() {
			if(this.state=="displaying"){
				// in the process of fading in.  wait until that is finished and then fade out
				this.eraseScheduled=true;
				return;
			}
			if ( this.state=="displayed" ) {
				this.state="erasing";
				if ( this.showTimer ) {
					clearTimeout(this.showTimer);
					delete this.showTimer;
				}
				if ( this.hideTimer ) {
					clearTimeout(this.hideTimer);
					delete this.hideTimer;
				}
				dojo.event.disconnect(document.documentElement, "onmousemove", this, "onMouseMove");
				dojo.widget.html.Tooltip.superclass.hide.call(this);
			}
		},
	
		onHide: function(){
			this.state="erased";
	
			// in the corner case where the user has moved his mouse back
			// while the tip was fading out
			if(this.displayScheduled){
				this.display();
				this.displayScheduled=false;
			}
		},
	
		position: function(){
			dojo.html.placeOnScreenPoint(this.domNode, this.mouse.x, this.mouse.y, [10,15], true);
			this.bgIframe.onResized();
		},
	
		onLoad: function(){
			if(this.isShowing()){
				// the tooltip has changed size due to downloaded contents, so reposition it
				dojo.lang.setTimeout(this, this.position, 50);
				dojo.widget.html.Tooltip.superclass.onLoad.apply(this, arguments);
			}
		},
	
		checkSize: function() {
			// checkSize() is called when the user has resized the browser window,
			// but that doesn't affect this widget (or this widget's children)
			// so it can be safely ignored
		}
	}
);
