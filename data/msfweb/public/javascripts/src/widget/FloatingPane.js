/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.FloatingPane");
dojo.provide("dojo.widget.html.FloatingPane");

//
// this widget provides a window-like floating pane
//

dojo.require("dojo.widget.*");
dojo.require("dojo.widget.Manager");
dojo.require("dojo.html");
dojo.require("dojo.html.shadow");
dojo.require("dojo.style");
dojo.require("dojo.dom");
dojo.require("dojo.html.layout");
dojo.require("dojo.widget.ContentPane");
dojo.require("dojo.dnd.HtmlDragMove");
dojo.require("dojo.dnd.HtmlDragMoveSource");
dojo.require("dojo.dnd.HtmlDragMoveObject");
dojo.require("dojo.widget.ResizeHandle");

dojo.widget.html.FloatingPane = function(){
	dojo.widget.html.ContentPane.call(this);
}

dojo.inherits(dojo.widget.html.FloatingPane, dojo.widget.html.ContentPane);

dojo.lang.extend(dojo.widget.html.FloatingPane, {
	widgetType: "FloatingPane",

	// Constructor arguments
	title: '',
	iconSrc: '',
	hasShadow: false,
	constrainToContainer: false,
	taskBarId: "",
	resizable: true,
	titleBarDisplay: "fancy",

	windowState: "normal",
	displayCloseAction: false,
	displayMinimizeAction: false,
	displayMaximizeAction: false,

	maxTaskBarConnectAttempts: 5,
	taskBarConnectAttempts: 0,

	templatePath: dojo.uri.dojoUri("src/widget/templates/HtmlFloatingPane.html"),
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlFloatingPane.css"),

	drag: null,

	fillInTemplate: function(args, frag){
		// Copy style info from input node to output node
		var source = this.getFragNodeRef(frag);
		dojo.html.copyStyle(this.domNode, source);

		// necessary for safari, khtml (for computing width/height)
		document.body.appendChild(this.domNode);

		// if display:none then state=minimized, otherwise state=normal
		if(!this.isShowing()){
			this.windowState="minimized";
		}

		// <img src=""> can hang IE!  better get rid of it
		if(this.iconSrc==""){
			dojo.dom.removeNode(this.titleBarIcon);
		}else{
			this.titleBarIcon.src = this.iconSrc.toString();// dojo.uri.Uri obj req. toString()
		}

		if(this.titleBarDisplay!="none"){	
			this.titleBar.style.display="";
			dojo.html.disableSelection(this.titleBar);

			this.titleBarIcon.style.display = (this.iconSrc=="" ? "none" : "");

			this.minimizeAction.style.display = (this.displayMinimizeAction ? "" : "none");
			this.maximizeAction.style.display= 
				(this.displayMaximizeAction && this.windowState!="maximized" ? "" : "none");
			this.restoreAction.style.display= 
				(this.displayMaximizeAction && this.windowState=="maximized" ? "" : "none");
			this.closeAction.style.display= (this.displayCloseAction ? "" : "none");

			this.drag = new dojo.dnd.HtmlDragMoveSource(this.domNode);	
			if (this.constrainToContainer) {
				this.drag.constrainTo();
			}
			this.drag.setDragHandle(this.titleBar);

			var self = this;

			dojo.event.topic.subscribe("dragMove",
				function (info){
					if (info.source.domNode == self.domNode){
						dojo.event.topic.publish('floatingPaneMove', { source: self } );
					}
				}
			);

		}

		if(this.resizable){
			this.resizeBar.style.display="";
			var rh = dojo.widget.createWidget("ResizeHandle", {targetElmId: this.widgetId, id:this.widgetId+"_resize"});
			this.resizeBar.appendChild(rh.domNode);
		}

		// add a drop shadow
		if(this.hasShadow){
			this.shadow=new dojo.html.shadow(this.domNode);
		}

		// Prevent IE bleed-through problem
		this.bgIframe = new dojo.html.BackgroundIframe(this.domNode);

		if( this.taskBarId ){
			this.taskBarSetup();
		}

		if (dojo.hostenv.post_load_) {
			this.setInitialWindowState();
		} else {
			dojo.addOnLoad(this, "setInitialWindowState");
		}

		// counteract body.appendChild above
		document.body.removeChild(this.domNode);

		dojo.widget.html.FloatingPane.superclass.fillInTemplate.call(this, args, frag);
	},

	postCreate: function(){
		if(this.isShowing()){
			this.width=-1;	// force resize
			this.resizeTo(dojo.style.getOuterWidth(this.domNode), dojo.style.getOuterHeight(this.domNode));
		}
	},

	maximizeWindow: function(evt) {
		this.previous={
			width: dojo.style.getOuterWidth(this.domNode) || this.width,
			height: dojo.style.getOuterHeight(this.domNode) || this.height,
			left: this.domNode.style.left,
			top: this.domNode.style.top,
			bottom: this.domNode.style.bottom,
			right: this.domNode.style.right
		};
		this.domNode.style.left =
			dojo.style.getPixelValue(this.domNode.parentNode, "padding-left", true) + "px";
		this.domNode.style.top =
			dojo.style.getPixelValue(this.domNode.parentNode, "padding-top", true) + "px";

		if ((this.domNode.parentNode.nodeName.toLowerCase() == 'body')) {
			this.resizeTo(
				dojo.html.getViewportWidth()-dojo.style.getPaddingWidth(document.body),
				dojo.html.getViewportHeight()-dojo.style.getPaddingHeight(document.body)
			);
		} else {
			this.resizeTo(
				dojo.style.getContentWidth(this.domNode.parentNode),
				dojo.style.getContentHeight(this.domNode.parentNode)
			);
		}
		this.maximizeAction.style.display="none";
		this.restoreAction.style.display="";
		this.windowState="maximized";
	},

	minimizeWindow: function(evt) {
		this.hide();
		this.windowState = "minimized";
	},

	restoreWindow: function(evt) {
		if (this.windowState=="minimized") {
			this.show() 
		} else {
			for(var attr in this.previous){
				this.domNode.style[attr] = this.previous[attr];
			}
			this.resizeTo(this.previous.width, this.previous.height);
			this.previous=null;

			this.restoreAction.style.display="none";
			this.maximizeAction.style.display=this.displayMaximizeAction ? "" : "none";
		}

		this.windowState="normal";
	},

	closeWindow: function(evt) {
		dojo.dom.removeNode(this.domNode);
		this.destroy();
	},

	onMouseDown: function(evt) {
		this.bringToTop();
	},

	bringToTop: function() {
		var floatingPanes= dojo.widget.manager.getWidgetsByType(this.widgetType);
		var windows = [];
		for (var x=0; x<floatingPanes.length; x++) {
			if (this.widgetId != floatingPanes[x].widgetId) {
					windows.push(floatingPanes[x]);
			}
		}

		windows.sort(function(a,b) {
			return a.domNode.style.zIndex - b.domNode.style.zIndex;
		});
		
		windows.push(this);

		var floatingPaneStartingZ = 100;
		for (x=0; x<windows.length;x++) {
			windows[x].domNode.style.zIndex = floatingPaneStartingZ + x;
		}
	},

	setInitialWindowState: function() {
		if (this.windowState == "maximized") {
			this.maximizeWindow();
			this.show();
			return;
		}

		if (this.windowState=="normal") {
			this.show();
			return;
		}

		if (this.windowState=="minimized") {
			this.hide();
			return;
		}

		this.windowState="minimized";
	},

	// add icon to task bar, connected to me
	taskBarSetup: function() {
		var taskbar = dojo.widget.getWidgetById(this.taskBarId);
		if (!taskbar){
			if (this.taskBarConnectAttempts <  this.maxTaskBarConnectAttempts) {
				dojo.lang.setTimeout(this, this.taskBarSetup, 50);
				this.taskBarConnectAttempts++;
			} else {
				dojo.debug("Unable to connect to the taskBar");
			}
			return;
		}
		taskbar.addChild(this);
	},

	show: function(){
		dojo.widget.html.FloatingPane.superclass.show.apply(this, arguments);
		this.bringToTop();
	},

	onShow: function(){
		dojo.widget.html.FloatingPane.superclass.onShow.call(this);
		this.resizeTo(dojo.style.getOuterWidth(this.domNode), dojo.style.getOuterHeight(this.domNode));
	},

	// This is called when the user adjusts the size of the floating pane
	resizeTo: function(w, h){
		dojo.style.setOuterWidth(this.domNode, w);
		dojo.style.setOuterHeight(this.domNode, h);

		dojo.html.layout(this.domNode,
			[
			  {domNode: this.titleBar, layoutAlign: "top"},
			  {domNode: this.resizeBar, layoutAlign: "bottom"},
			  {domNode: this.containerNode, layoutAlign: "client"}
			] );

		// If any of the children have layoutAlign specified, obey it
		dojo.html.layout(this.containerNode, this.children, "top-bottom");
		
		this.bgIframe.onResized();
		if(this.shadow){ this.shadow.size(w, h); }
		this.onResized();
	},

	checkSize: function() {
		// checkSize() is called when the user has resized the browser window,
		// but that doesn't affect this widget (or this widget's children)
		// so it can be safely ignored...
		// TODO: unless we are maximized.  then we should resize ourself.
	}
});

dojo.widget.tags.addParseTreeHandler("dojo:FloatingPane");
