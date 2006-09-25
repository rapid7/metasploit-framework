/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.ResizeHandle");
dojo.provide("dojo.widget.html.ResizeHandle");

dojo.require("dojo.widget.*");
dojo.require("dojo.html");
dojo.require("dojo.style");
dojo.require("dojo.dom");
dojo.require("dojo.event");

dojo.widget.html.ResizeHandle = function(){
	dojo.widget.HtmlWidget.call(this);
}

dojo.inherits(dojo.widget.html.ResizeHandle, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.html.ResizeHandle, {
	widgetType: "ResizeHandle",

	isSizing: false,
	startPoint: null,
	startSize: null,
	minSize: null,

	targetElmId: '',

	templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlResizeHandle.css"),
	templateString: '<div class="dojoHtmlResizeHandle"><div></div></div>',

	postCreate: function(){
		dojo.event.connect(this.domNode, "onmousedown", this, "beginSizing");
	},

	beginSizing: function(e){
		if (this.isSizing){ return false; }

		// get the target dom node to adjust.  targetElmId can refer to either a widget or a simple node
		this.targetWidget = dojo.widget.byId(this.targetElmId);
		this.targetDomNode = this.targetWidget ? this.targetWidget.domNode : dojo.byId(this.targetElmId);
		if (!this.targetDomNode){ return; }

		this.isSizing = true;
		this.startPoint  = {'x':e.clientX, 'y':e.clientY};
		this.startSize  = {'w':dojo.style.getOuterWidth(this.targetDomNode), 'h':dojo.style.getOuterHeight(this.targetDomNode)};

		dojo.event.kwConnect({
			srcObj: document.body, 
			srcFunc: "onmousemove",
			targetObj: this,
			targetFunc: "changeSizing",
			rate: 25
		});
		dojo.event.connect(document.body, "onmouseup", this, "endSizing");

		e.preventDefault();
	},

	changeSizing: function(e){
		// On IE, if you move the mouse above/to the left of the object being resized,
		// sometimes clientX/Y aren't set, apparently.  Just ignore the event.
		try{
			if(!e.clientX  || !e.clientY){ return; }
		}catch(e){
			// sometimes you get an exception accessing above fields...
			return;
		}
		var dx = this.startPoint.x - e.clientX;
		var dy = this.startPoint.y - e.clientY;
		
		var newW = this.startSize.w - dx;
		var newH = this.startSize.h - dy;

		// minimum size check
		if (this.minSize) {
			if (newW < this.minSize.w) {
				newW = dojo.style.getOuterWidth(this.targetDomNode);
			}
			if (newH < this.minSize.h) {
				newH = dojo.style.getOuterHeight(this.targetDomNode);
			}
		}
		
		if(this.targetWidget){
			this.targetWidget.resizeTo(newW, newH);
		}else{
			dojo.style.setOuterWidth(this.targetDomNode, newW);
			dojo.style.setOuterHeight(this.targetDomNode, newH);
		}
		
		e.preventDefault();
	},

	endSizing: function(e){
		dojo.event.disconnect(document.body, "onmousemove", this, "changeSizing");
		dojo.event.disconnect(document.body, "onmouseup", this, "endSizing");

		this.isSizing = false;
	}


});

dojo.widget.tags.addParseTreeHandler("dojo:ResizeHandle");
