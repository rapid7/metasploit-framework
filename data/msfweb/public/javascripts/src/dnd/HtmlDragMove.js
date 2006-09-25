/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.dnd.HtmlDragMove");
dojo.provide("dojo.dnd.HtmlDragMoveSource");
dojo.provide("dojo.dnd.HtmlDragMoveObject");
dojo.require("dojo.dnd.*");

dojo.dnd.HtmlDragMoveSource = function(node, type){
	dojo.dnd.HtmlDragSource.call(this, node, type);
}
dojo.inherits(dojo.dnd.HtmlDragMoveSource, dojo.dnd.HtmlDragSource);
dojo.lang.extend(dojo.dnd.HtmlDragMoveSource, {
	onDragStart: function(){
		var dragObj =  new dojo.dnd.HtmlDragMoveObject(this.dragObject, this.type);
		if (this.constrainToContainer) {
			dragObj.constrainTo(this.constrainingContainer);
		}
		return dragObj;
	},
	/*
	 * see dojo.dnd.HtmlDragSource.onSelected
	 */
	onSelected: function() {
		for (var i=0; i<this.dragObjects.length; i++) {
			dojo.dnd.dragManager.selectedSources.push(new dojo.dnd.HtmlDragMoveSource(this.dragObjects[i]));
		}
	}
});

dojo.dnd.HtmlDragMoveObject = function(node, type){
	dojo.dnd.HtmlDragObject.call(this, node, type);
}
dojo.inherits(dojo.dnd.HtmlDragMoveObject, dojo.dnd.HtmlDragObject);
dojo.lang.extend(dojo.dnd.HtmlDragMoveObject, {
	onDragEnd: function(e){
		// shortly the browser will fire an onClick() event,
		// but since this was really a drag, just squelch it
		dojo.event.connect(this.domNode, "onclick", this, "squelchOnClick");
	},
	onDragStart: function(e){
		dojo.html.clearSelection();

		this.dragClone = this.domNode;

		this.scrollOffset = dojo.html.getScrollOffset();
		this.dragStartPosition = dojo.style.getAbsolutePosition(this.domNode, true);
		
		this.dragOffset = {y: this.dragStartPosition.y - e.pageY,
			x: this.dragStartPosition.x - e.pageX};

		this.containingBlockPosition = this.domNode.offsetParent ? 
			dojo.style.getAbsolutePosition(this.domNode.offsetParent, true) : {x:0, y:0};

		this.dragClone.style.position = "absolute";

		if (this.constrainToContainer) {
			this.constraints = this.getConstraints();
		}
	},
	/**
	 * Set the position of the drag node.  (x,y) is relative to <body>.
	 */
	setAbsolutePosition: function(x, y){
		// The drag clone is attached to it's constraining container so offset for that
		if(!this.disableY) { this.domNode.style.top = (y-this.containingBlockPosition.y) + "px"; }
		if(!this.disableX) { this.domNode.style.left = (x-this.containingBlockPosition.x) + "px"; }
	}
});
