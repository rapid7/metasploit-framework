/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.ContextMenu");
dojo.require("dojo.html");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.widget.ContextMenu");
dojo.require("dojo.lang");

dojo.widget.html.ContextMenu = function(){
	dojo.widget.ContextMenu.call(this);
	dojo.widget.HtmlWidget.call(this);

	this.isShowing = 0;
	this.templatePath = dojo.uri.dojoUri("src/widget/templates/HtmlContextMenuTemplate.html");
	this.templateCssPath = dojo.uri.dojoUri("src/widget/templates/Menu.css");

	this.targetNodeIds = []; // fill this with nodeIds upon widget creation and it only responds to those nodes

	// default event detection method 
	var eventType = "oncontextmenu"; 

	var doc = document.documentElement  || document.body; 

	var _blockHide = false; 

	this.fillInTemplate = function(args, frag){

		var func = "onOpen";
		var attached = false;

		// connect with rightclick if oncontextmenu is not around
		// NOTE: It would be very nice to have a dojo.event.browser.supportsEvent here
		// NOTE: Opera does not have rightclick events, it is listed here only because
		//     it bails out when connecting with oncontextmenu event

		if((dojo.render.html.khtml && !dojo.render.html.safari) || (dojo.render.html.opera)){
			eventType = "onmousedown";
			func = "_checkRightClick";
		}

		// attach event listeners to our selected nodes
		for(var i=0; i<this.targetNodeIds.length; i++){
			var node = document.getElementById(this.targetNodeIds[i]);
			if(node){
				dojo.event.connect(node, eventType, this, func);
				attached = true;
			}else{
				// remove this nodeId
				dojo.debug("Couldent find "+this.targetNodeIds[i]+", cant do ContextMenu on this node");
				this.targetNodeIds.splice(i,1);
			}
		}

		// if we got attached to a node, hide on all non node contextevents
		if(attached){ func = "_canHide"; }

		dojo.event.connect(doc, eventType, this, func);
	}

	this.onOpen = function(evt){
		// if (this.isShowing){ this.onHide(evt); } // propably not needed
		this.isShowing = 1;

		// if I do this, I cant preventDefault in khtml
		//evt = dojo.event.browser.fixEvent(evt);
 
		// stop default contextmenu, needed in khtml
		if (evt.preventDefault){ evt.preventDefault(); }

		// need to light up this one before we check width and height
		this.domNode.style.left = "-9999px";
		this.domNode.style.top  = "-9999px";
		this.domNode.style.display = "block";

		// calculate if menu is going to apear within window
		// or if its partially out of visable area
		with(dojo.html){

			var menuW = getInnerWidth(this.domNode);
			var menuH = getInnerHeight(this.domNode);

			var viewport = getViewportSize();
			var scrolloffset = getScrollOffset();
		}

		var minX = viewport[0];
		var minY = viewport[1];

		var maxX = (viewport[0] + scrolloffset[0]) - menuW;
		var maxY = (viewport[1] + scrolloffset[1]) - menuH;

		var posX = evt.clientX + scrolloffset[0];
		var posY = evt.clientY + scrolloffset[1];

		if (posX > maxX){ posX = posX - menuW; }
		if (posY > maxY){ posY = posY - menuH; }

		this.domNode.style.left = posX + "px";
		this.domNode.style.top = posY + "px";


		// block the onclick that follows this particular right click
		// not if the eventtrigger is documentElement and always when
		// we use onmousedown hack
		_blockHide = (evt.currentTarget!=doc || eventType=='onmousedown');

		//return false; // we propably doesnt need to return false as we dont stop the event as we did before
	}

	/*
	* _canHide is meant to block the onHide call that follows the event that triggered
	* onOpen. This is (hopefully) faster that event.connect and event.disconnect every
	* time the code executes and it makes connecting with onmousedown event possible
	* and we dont have to stop the event from bubbling further.
	*
	* this code is moved into a separete function because it makes it possible for the
	* user to connect to a onHide event, if anyone would like that.
	*/

	this._canHide = function(evt){
		// block the onclick that follows the same event that turn on contextmenu
		if(_blockHide){
			// the onclick check is needed to prevent displaying multiple
			// menus when we have 2 or more contextmenus loaded and are using
			// the onmousedown hack
			if(evt.type=='click' || eventType=='oncontextmenu'){
				_blockHide = false;
				return;
			}else{
				return;
			}
		}

		this.onHide(evt);
	}
	
	this.onHide = function(evt){
		// FIXME: use whatever we use to do more general style setting?
		this.domNode.style.display = "none";
		//dojo.event.disconnect(doc, "onclick", this, "onHide");
		this.isShowing = 0;
	}

	// callback for rightclicks, needed for browsers that doesnt implement oncontextmenu, konqueror and more? 
	this._checkRightClick = function(evt){ 

		// for some reason konq comes here even when we are not clicking on the attached nodes 
		// added check for targetnode 
		if (evt.button==2 && (this.targetNodeIds.length==0 || (evt.currentTarget.id!="" && dojo.lang.inArray(this.targetNodeIds, evt.currentTarget.id)))){

			return this.onOpen(evt);
		}
	}

	dojo.event.connect(doc, "onclick", this, "_canHide");
}

dojo.inherits(dojo.widget.html.ContextMenu, dojo.widget.HtmlWidget);
