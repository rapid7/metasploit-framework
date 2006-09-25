/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/


dojo.provide("dojo.widget.TreeBasicController");

dojo.require("dojo.event.*");
dojo.require("dojo.json")
dojo.require("dojo.io.*");


dojo.widget.tags.addParseTreeHandler("dojo:TreeBasicController");


dojo.widget.TreeBasicController = function() {
	dojo.widget.HtmlWidget.call(this);
}

dojo.inherits(dojo.widget.TreeBasicController, dojo.widget.HtmlWidget);


dojo.lang.extend(dojo.widget.TreeBasicController, {
	widgetType: "TreeBasicController",

	DNDController: "",

	dieWithTree: false,

	initialize: function(args, frag){

		/* no DND by default for compatibility */
		if (this.DNDController == "create") {
			dojo.require("dojo.dnd.TreeDragAndDrop");
			this.DNDController = new dojo.dnd.TreeDNDController(this);
		}



	},


	/**
	 * Binds controller to all tree events
	*/
	listenTree: function(tree) {
		//dojo.debug("Event "+tree.eventNames.treeClick);
		dojo.event.topic.subscribe(tree.eventNames.createDOMNode, this, "onCreateDOMNode");
		dojo.event.topic.subscribe(tree.eventNames.treeClick, this, "onTreeClick");
		dojo.event.topic.subscribe(tree.eventNames.treeCreate, this, "onTreeCreate");
		dojo.event.topic.subscribe(tree.eventNames.treeDestroy, this, "onTreeDestroy");

		if (this.DNDController) {
			this.DNDController.listenTree(tree);
		}
	},

	unlistenTree: function(tree) {
		dojo.event.topic.unsubscribe(tree.eventNames.createDOMNode, this, "onCreateDOMNode");
		dojo.event.topic.unsubscribe(tree.eventNames.treeClick, this, "onTreeClick");
		dojo.event.topic.unsubscribe(tree.eventNames.treeCreate, this, "onTreeCreate");
		dojo.event.topic.unsubscribe(tree.eventNames.treeDestroy, this, "onTreeDestroy");
	},

	onTreeDestroy: function(message) {
		var tree = message.source;

		this.unlistenTree(tree);

		if (this.dieWithTree) {
			//alert("Killing myself "+this.widgetId);
			this.destroy();
			//dojo.debug("done");
		}
	},

	onCreateDOMNode: function(message) {

		var node = message.source;


		if (node.expandLevel > 0) {
			this.expandToLevel(node, node.expandLevel);
		}
	},

	// perform actions-initializers for tree
	onTreeCreate: function(message) {
		var tree = message.source;
		var _this = this;
		if (tree.expandLevel) {
			dojo.lang.forEach(tree.children,
				function(child) {
					_this.expandToLevel(child, tree.expandLevel-1)
				}
			);
		}
	},

	expandToLevel: function(node, level) {
		if (level == 0) return;

		var children = node.children;
		var _this = this;

		var handler = function(node, expandLevel) {
			this.node = node;
			this.expandLevel = expandLevel;
			// recursively expand opened node
			this.process = function() {
				//dojo.debug("Process "+node+" level "+level);
				for(var i=0; i<this.node.children.length; i++) {
					var child = node.children[i];

					_this.expandToLevel(child, this.expandLevel);
				}
			};
		}

		var h = new handler(node, level-1);


		this.expand(node, false, h, h.process);

	},




	onTreeClick: function(message){
		var node = message.source;

		if(node.isLocked()) {
			return false;
		}

		if (node.isExpanded){
			this.collapse(node);
		} else {
			this.expand(node);
		}
	},

	expand: function(node, sync, callObj, callFunc) {
		node.expand();
		if (callFunc) callFunc.apply(callObj, [node]);
	},

	collapse: function(node) {

		node.collapse();
	},

// =============================== move ============================

	/**
	 * Checks whether it is ok to change parent of child to newParent
	 * May incur type checks etc
	 *
	 * It should check only hierarchical possibility w/o index, etc
	 * because in onDragOver event for Between DND mode we can't calculate index at once on onDragOVer.
	 * index changes as client moves mouse up-down over the node
	 */
	canMove: function(child, newParent){

		if (child.actionIsDisabled(child.actions.MOVE)) {
			return false;
		}

		// if we move under same parent then no matter if ADDCHILD disabled for him
		// but if we move to NEW parent then check if action is disabled for him
		// also covers case for newParent being a non-folder in strict mode etc
		if (child.parent !== newParent && newParent.actionIsDisabled(newParent.actions.ADDCHILD)) {
			return false;
		}

		// Can't move parent under child. check whether new parent is child of "child".
		var node = newParent;
		while(node.isTreeNode) {
			//dojo.debugShallow(node.title)
			if (node === child) {
				// parent of newParent is child
				return false;
			}
			node = node.parent;
		}

		return true;
	},


	move: function(child, newParent, index) {

		/* move sourceTreeNode to new parent */
		if (!this.canMove(child, newParent)) {
			return false;
		}

		var result = this.doMove(child, newParent, index);

		if (!result) return result;

		if (newParent.isTreeNode) {
			this.expand(newParent);
		}

		return result;
	},

	doMove: function(child, newParent, index) {
		child.tree.move(child, newParent, index);

		return true;
	},

// =============================== removeNode ============================


	canRemoveNode: function(child) {
		if (child.actionIsDisabled(child.actions.REMOVE)) {
			return false;
		}

		return true;
	},


	removeNode: function(node, callObj, callFunc) {
		if (!this.canRemoveNode(node)) {
			return false;
		}

		return this.doRemoveNode(node, callObj, callFunc);
	},


	doRemoveNode: function(node, callObj, callFunc) {
		node.tree.removeNode(node);

		if (callFunc) {
			callFunc.apply(dojo.lang.isUndefined(callObj) ? this : callObj, [node]);
		}
	},


	// -----------------------------------------------------------------------------
	//                             Create node stuff
	// -----------------------------------------------------------------------------


	canCreateChild: function(parent, index, data) {
		if (parent.actionIsDisabled(parent.actions.ADDCHILD)) return false;

		return true;
	},


	/* send data to server and add child from server */
	/* data may contain an almost ready child, or anything else, suggested to server */
	/*in RPC controllers server responds with child data to be inserted */
	createChild: function(parent, index, data, callObj, callFunc) {
		if (!this.canCreateChild(parent, index, data)) {
			return false;
		}

		return this.doCreateChild.apply(this, arguments);
	},

	doCreateChild: function(parent, index, data, callObj, callFunc) {

		var widgetType = data.widgetType ? data.widgetType : "TreeNode";

		var newChild = dojo.widget.createWidget(widgetType, data);

		parent.addChild(newChild, index);

		this.expand(parent);

		if (callFunc) {
			callFunc.apply(callObj, [newChild]);
		}

		return newChild;
	}



});
