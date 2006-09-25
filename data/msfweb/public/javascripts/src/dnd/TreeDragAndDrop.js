/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/**
 * TreeDrag* specialized on managing subtree drags
 * It selects nodes and visualises what's going on,
 * but delegates real actions upon tree to the controller
 *
 * This code is considered a part of controller
*/

dojo.provide("dojo.dnd.TreeDragAndDrop");
dojo.provide("dojo.dnd.TreeDragSource");
dojo.provide("dojo.dnd.TreeDropTarget");
dojo.provide("dojo.dnd.TreeDNDController");

dojo.require("dojo.dnd.HtmlDragAndDrop");
dojo.require("dojo.lang.func");
dojo.require("dojo.lang.array");
dojo.require("dojo.lang.extras");

dojo.dnd.TreeDragSource = function(node, syncController, type, treeNode){
	this.controller = syncController;
	this.treeNode = treeNode;

	dojo.dnd.HtmlDragSource.call(this, node, type);
}

dojo.inherits(dojo.dnd.TreeDragSource, dojo.dnd.HtmlDragSource);

dojo.lang.extend(dojo.dnd.TreeDragSource, {
	onDragStart: function(){
		/* extend adds functions to prototype */
		var dragObject = dojo.dnd.HtmlDragSource.prototype.onDragStart.call(this);
		//dojo.debugShallow(dragObject)

		dragObject.treeNode = this.treeNode;

		dragObject.onDragStart = dojo.lang.hitch(dragObject, function(e) {

			/* save selection */
			this.savedSelectedNode = this.treeNode.tree.selector.selectedNode;
			if (this.savedSelectedNode) {
				this.savedSelectedNode.unMarkSelected();
			}

			var result = dojo.dnd.HtmlDragObject.prototype.onDragStart.apply(this, arguments);


			/* remove background grid from cloned object */
			var cloneGrid = this.dragClone.getElementsByTagName('img');
			for(var i=0; i<cloneGrid.length; i++) {
				cloneGrid.item(i).style.backgroundImage='url()';
			}

			return result;


		});

		dragObject.onDragEnd = function(e) {

			/* restore selection */
			if (this.savedSelectedNode) {
				this.savedSelectedNode.markSelected();
			}
			//dojo.debug(e.dragStatus);

			return dojo.dnd.HtmlDragObject.prototype.onDragEnd.apply(this, arguments);
		}
		//dojo.debug(dragObject.domNode.outerHTML)


		return dragObject;
	},

	onDragEnd: function(e){


		 var res = dojo.dnd.HtmlDragSource.prototype.onDragEnd.call(this, e);


		 return res;
	}
});

// .......................................

dojo.dnd.TreeDropTarget = function(domNode, controller, type, treeNode, DNDMode){

	this.treeNode = treeNode;
	this.controller = controller; // I will sync-ly process drops
	this.DNDMode = DNDMode;

	dojo.dnd.HtmlDropTarget.apply(this, [domNode, type]);
}

dojo.inherits(dojo.dnd.TreeDropTarget, dojo.dnd.HtmlDropTarget);

dojo.lang.extend(dojo.dnd.TreeDropTarget, {

	autoExpandDelay: 1500,
	autoExpandTimer: null,


	position: null,

	indicatorStyle: "2px black solid",

	showIndicator: function(position) {

		// do not change style too often, cause of blinking possible
		if (this.position == position) {
			return;
		}

		//dojo.debug(position)

		this.hideIndicator();

		this.position = position;

		if (position == "before") {
			this.treeNode.labelNode.style.borderTop = this.indicatorStyle;
		} else if (position == "after") {
			this.treeNode.labelNode.style.borderBottom = this.indicatorStyle;
		} else if (position == "onto") {
			this.treeNode.markSelected();
		}


	},

	hideIndicator: function() {
		this.treeNode.labelNode.style.borderBottom="";
		this.treeNode.labelNode.style.borderTop="";
		this.treeNode.unMarkSelected();
		this.position = null;
	},



	// is the target possibly ok ?
	// This function is run on dragOver, but drop possibility is also determined by position over node
	// that's why acceptsWithPosition is called
	// doesnt take index into account ( can change while moving mouse w/o changing target )


	/**
	 * Coarse (tree-level) access check.
	 * We can't determine real accepts status w/o position
	*/
	onDragOver: function(e){
//dojo.debug("onDragOver for "+e);


		var accepts = dojo.dnd.HtmlDropTarget.prototype.onDragOver.apply(this, arguments);

		//dojo.debug("TreeDropTarget.onDragOver accepts:"+accepts)

		if (accepts && this.treeNode.isFolder && !this.treeNode.isExpanded) {
			this.setAutoExpandTimer();
		}

		return accepts;
	},

	/* Parent.onDragOver calls this function to get accepts status */
	accepts: function(dragObjects) {

		var accepts = dojo.dnd.HtmlDropTarget.prototype.accepts.apply(this, arguments);

		if (!accepts) return false;

		var sourceTreeNode = dragObjects[0].treeNode;

		if (dojo.lang.isUndefined(sourceTreeNode) || !sourceTreeNode || !sourceTreeNode.isTreeNode) {
			dojo.raise("Source is not TreeNode or not found");
		}

		if (sourceTreeNode === this.treeNode) return false;

		return true;
	},



	setAutoExpandTimer: function() {
		// set up autoexpand timer
		var _this = this;

		var autoExpand = function () {
			if (dojo.dnd.dragManager.currentDropTarget === _this) {
				_this.controller.expand(_this.treeNode);
			}
		}

		this.autoExpandTimer = dojo.lang.setTimeout(autoExpand, _this.autoExpandDelay);
	},


	getAcceptPosition: function(e, sourceTreeNode) {

		var DNDMode = this.DNDMode;

		if (DNDMode & dojo.widget.Tree.prototype.DNDModes.ONTO &&
			// check if ONTO is allowed localy
			!(
			  !this.treeNode.actionIsDisabled(dojo.widget.TreeNode.prototype.actions.ADDCHILD) // check dynamically cause may change w/o regeneration of dropTarget
			  && sourceTreeNode.parent !== this.treeNode
			  && this.controller.canMove(sourceTreeNode, this.treeNode)
			 )
		) {
			// disable ONTO if can't move
			DNDMode &= ~dojo.widget.Tree.prototype.DNDModes.ONTO;
		}


		var position = this.getPosition(e, DNDMode);

		//dojo.debug(DNDMode & +" : "+position);


		// if onto is here => it was allowed before, no accept check is needed
		if (position=="onto" ||
			(!this.isAdjacentNode(sourceTreeNode, position)
			 && this.controller.canMove(sourceTreeNode, this.treeNode.parent)
			)
		) {
			return position;
		} else {
			return false;
		}

	},

	onDragOut: function(e) {
		this.clearAutoExpandTimer();

		this.hideIndicator();
	},


	clearAutoExpandTimer: function() {
		if (this.autoExpandTimer) {
			clearTimeout(this.autoExpandTimer);
			this.autoExpandTimer = null;
		}
	},



	onDragMove: function(e, dragObjects){

		var sourceTreeNode = dragObjects[0].treeNode;

		var position = this.getAcceptPosition(e, sourceTreeNode);

		if (position) {
			this.showIndicator(position);
		}

	},

	isAdjacentNode: function(sourceNode, position) {

		if (sourceNode === this.treeNode) return true;
		if (sourceNode.getNextSibling() === this.treeNode && position=="before") return true;
		if (sourceNode.getPreviousSibling() === this.treeNode && position=="after") return true;

		return false;
	},


	/* get DNDMode and see which position e fits */
	getPosition: function(e, DNDMode) {
		node = dojo.byId(this.treeNode.labelNode);
		var mousey = e.pageY || e.clientY + document.body.scrollTop;
		var nodey = dojo.html.getAbsoluteY(node);
		var height = dojo.html.getInnerHeight(node);

		var relY = mousey - nodey;
		var p = relY / height;

		var position = ""; // "" <=> forbidden
		if (DNDMode & dojo.widget.Tree.prototype.DNDModes.ONTO
		  && DNDMode & dojo.widget.Tree.prototype.DNDModes.BETWEEN) {
			if (p<=0.3) {
				position = "before";
			} else if (p<=0.7) {
				position = "onto";
			} else {
				position = "after";
			}
		} else if (DNDMode & dojo.widget.Tree.prototype.DNDModes.BETWEEN) {
			if (p<=0.5) {
				position = "before";
			} else {
				position = "after";
			}
		}
		else if (DNDMode & dojo.widget.Tree.prototype.DNDModes.ONTO) {
			position = "onto";
		}


		return position;
	},



	getTargetParentIndex: function(sourceTreeNode, position) {

		var index = position == "before" ? this.treeNode.getParentIndex() : this.treeNode.getParentIndex()+1;
		if (this.treeNode.parent === sourceTreeNode.parent
		  && this.treeNode.getParentIndex() > sourceTreeNode.getParentIndex()) {
		  	index--;  // dragging a node is different for simple move bacause of before-after issues
		}

		return index;
	},


	onDrop: function(e){
		// onDragOut will clean position


		var position = this.position;

//dojo.debug(position);

		this.onDragOut(e);

		var sourceTreeNode = e.dragObject.treeNode;

		if (!dojo.lang.isObject(sourceTreeNode)) {
			dojo.raise("TreeNode not found in dragObject")
		}

		if (position == "onto") {
			return this.controller.move(sourceTreeNode, this.treeNode, 0);
		} else {
			var index = this.getTargetParentIndex(sourceTreeNode, position);
			return this.controller.move(sourceTreeNode, this.treeNode.parent, index);
		}

		//dojo.debug('drop2');



	}


});



dojo.dnd.TreeDNDController = function(treeController) {

	// I use this controller to perform actions
	this.treeController = treeController;

	this.dragSources = {};

	this.dropTargets = {};

}

dojo.lang.extend(dojo.dnd.TreeDNDController, {


	listenTree: function(tree) {
		//dojo.debug("Listen tree "+tree);
		dojo.event.topic.subscribe(tree.eventNames.createDOMNode, this, "onCreateDOMNode");
		dojo.event.topic.subscribe(tree.eventNames.moveFrom, this, "onMoveFrom");
		dojo.event.topic.subscribe(tree.eventNames.moveTo, this, "onMoveTo");
		dojo.event.topic.subscribe(tree.eventNames.addChild, this, "onAddChild");
		dojo.event.topic.subscribe(tree.eventNames.removeNode, this, "onRemoveNode");
		dojo.event.topic.subscribe(tree.eventNames.treeDestroy, this, "onTreeDestroy");
	},


	unlistenTree: function(tree) {
		//dojo.debug("Listen tree "+tree);
		dojo.event.topic.unsubscribe(tree.eventNames.createDOMNode, this, "onCreateDOMNode");
		dojo.event.topic.unsubscribe(tree.eventNames.moveFrom, this, "onMoveFrom");
		dojo.event.topic.unsubscribe(tree.eventNames.moveTo, this, "onMoveTo");
		dojo.event.topic.unsubscribe(tree.eventNames.addChild, this, "onAddChild");
		dojo.event.topic.unsubscribe(tree.eventNames.removeNode, this, "onRemoveNode");
		dojo.event.topic.unsubscribe(tree.eventNames.treeDestroy, this, "onTreeDestroy");
	},

	onTreeDestroy: function(message) {
		this.unlistenTree(message.source);
		// I'm not widget so don't use destroy() call and dieWithTree
	},

	onCreateDOMNode: function(message) {
		this.registerDNDNode(message.source);
	},

	onAddChild: function(message) {
		this.registerDNDNode(message.child);
	},

	onMoveFrom: function(message) {
		var _this = this;
		dojo.lang.forEach(
			message.child.getDescendants(),
			function(node) { _this.unregisterDNDNode(node); }
		);
	},

	onMoveTo: function(message) {
		var _this = this;
		dojo.lang.forEach(
			message.child.getDescendants(),
			function(node) { _this.registerDNDNode(node); }
		);
	},

	/**
	 * Controller(node model) creates DNDNodes because it passes itself to node for synchroneous drops processing
	 * I can't process DnD with events cause an event can't return result success/false
	*/
	registerDNDNode: function(node) {
		if (!node.tree.DNDMode) return;

//dojo.debug("registerDNDNode "+node);

		/* I drag label, not domNode, because large domNodes are very slow to copy and large to drag */

		var source = null;
		var target = null;

		if (!node.actionIsDisabled(node.actions.MOVE)) {
			//dojo.debug("reg source")
			var source = new dojo.dnd.TreeDragSource(node.labelNode, this, node.tree.widgetId, node);
			this.dragSources[node.widgetId] = source;
		}

		var target = new dojo.dnd.TreeDropTarget(node.labelNode, this.treeController, node.tree.DNDAcceptTypes, node, node.tree.DNDMode);

		this.dropTargets[node.widgetId] = target;

	},


	unregisterDNDNode: function(node) {

		if (this.dragSources[node.widgetId]) {
			dojo.dnd.dragManager.unregisterDragSource(this.dragSources[node.widgetId]);
			delete this.dragSources[node.widgetId];
		}

		if (this.dropTargets[node.widgetId]) {
			dojo.dnd.dragManager.unregisterDropTarget(this.dropTargets[node.widgetId]);
			delete this.dropTargets[node.widgetId];
		}
	}





});
