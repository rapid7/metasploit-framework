/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.require("dojo.lang");
dojo.provide("dojo.dnd.DragSource");
dojo.provide("dojo.dnd.DropTarget");
dojo.provide("dojo.dnd.DragObject");
dojo.provide("dojo.dnd.DragAndDrop");

dojo.dnd.DragSource = function(){
	var dm = dojo.dnd.dragManager;
	if(dm["registerDragSource"]){ // side-effect prevention
		dm.registerDragSource(this);
	}
}

dojo.lang.extend(dojo.dnd.DragSource, {
	type: "",

	onDragEnd: function(){
	},

	onDragStart: function(){
	},

	/*
	 * This function gets called when the DOM element was 
	 * selected for dragging by the HtmlDragAndDropManager.
	 */
	onSelected: function(){
	},

	unregister: function(){
		dojo.dnd.dragManager.unregisterDragSource(this);
	},

	reregister: function(){
		dojo.dnd.dragManager.registerDragSource(this);
	}
});

dojo.dnd.DragObject = function(){
	var dm = dojo.dnd.dragManager;
	if(dm["registerDragObject"]){ // side-effect prevention
		dm.registerDragObject(this);
	}
}

dojo.lang.extend(dojo.dnd.DragObject, {
	type: "",

	onDragStart: function(){
		// gets called directly after being created by the DragSource
		// default action is to clone self as icon
	},

	onDragMove: function(){
		// this changes the UI for the drag icon
		//	"it moves itself"
	},

	onDragOver: function(){
	},

	onDragOut: function(){
	},

	onDragEnd: function(){
	},

	// normal aliases
	onDragLeave: this.onDragOut,
	onDragEnter: this.onDragOver,

	// non-camel aliases
	ondragout: this.onDragOut,
	ondragover: this.onDragOver
});

dojo.dnd.DropTarget = function(){
	if (this.constructor == dojo.dnd.DropTarget) { return; } // need to be subclassed
	this.acceptedTypes = [];
	dojo.dnd.dragManager.registerDropTarget(this);
}

dojo.lang.extend(dojo.dnd.DropTarget, {

	acceptsType: function(type){
		if(!dojo.lang.inArray(this.acceptedTypes, "*")){ // wildcard
			if(!dojo.lang.inArray(this.acceptedTypes, type)) { return false; }
		}
		return true;
	},

	accepts: function(dragObjects){
		if(!dojo.lang.inArray(this.acceptedTypes, "*")){ // wildcard
			for (var i = 0; i < dragObjects.length; i++) {
				if (!dojo.lang.inArray(this.acceptedTypes,
					dragObjects[i].type)) { return false; }
			}
		}
		return true;
	},

	onDragOver: function(){
	},

	onDragOut: function(){
	},

	onDragMove: function(){
	},

	onDropStart: function(){
	},

	onDrop: function(){
	},

	onDropEnd: function(){
	}
});

// NOTE: this interface is defined here for the convenience of the DragManager
// implementor. It is expected that in most cases it will be satisfied by
// extending a native event (DOM event in HTML and SVG).
dojo.dnd.DragEvent = function(){
	this.dragSource = null;
	this.dragObject = null;
	this.target = null;
	this.eventStatus = "success";
	//
	// can be one of:
	//	[	"dropSuccess", "dropFailure", "dragMove",
	//		"dragStart", "dragEnter", "dragLeave"]
	//
}

dojo.dnd.DragManager = function(){
	/*
	 *	The DragManager handles listening for low-level events and dispatching
	 *	them to higher-level primitives like drag sources and drop targets. In
	 *	order to do this, it must keep a list of the items.
	 */
}

dojo.lang.extend(dojo.dnd.DragManager, {
	selectedSources: [],
	dragObjects: [],
	dragSources: [],
	registerDragSource: function(){},
	dropTargets: [],
	registerDropTarget: function(){},
	lastDragTarget: null,
	currentDragTarget: null,
	onKeyDown: function(){},
	onMouseOut: function(){},
	onMouseMove: function(){},
	onMouseUp: function(){}
});

// NOTE: despite the existance of the DragManager class, there will be a
// singleton drag manager provided by the renderer-specific D&D support code.
// It is therefore sane for us to assign instance variables to the DragManager
// prototype

// The renderer-specific file will define the following object:
// dojo.dnd.dragManager = null;
