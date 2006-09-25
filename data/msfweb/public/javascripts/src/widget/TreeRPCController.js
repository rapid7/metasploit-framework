/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/


dojo.provide("dojo.widget.TreeRPCController");

dojo.require("dojo.event.*");
dojo.require("dojo.json")
dojo.require("dojo.io.*");
dojo.require("dojo.widget.TreeLoadingController");

dojo.widget.tags.addParseTreeHandler("dojo:TreeRPCController");

dojo.widget.TreeRPCController = function(){
	dojo.widget.TreeLoadingController.call(this);
}

dojo.inherits(dojo.widget.TreeRPCController, dojo.widget.TreeLoadingController);

dojo.lang.extend(dojo.widget.TreeRPCController, {
	widgetType: "TreeRPCController",

	/**
	 * Make request to server about moving children.
	 *
	 * Request returns "true" if move succeeded,
	 * object with error field if failed
	 *
	 * I can't leave DragObject floating until async request returns, need to return false/true
	 * so making it sync way...
	 *
	 * Also, "loading" icon is not shown until function finishes execution, so no indication for remote request.
	*/
	doMove: function(child, newParent, index){

		//if (newParent.isTreeNode) newParent.markLoading();

		var params = {
			// where from
			child: this.getInfo(child),
			childTree: this.getInfo(child.tree),
			// where to
			newParent: this.getInfo(newParent),
			newParentTree: this.getInfo(newParent.tree),
			newIndex: index
		};

		var success;

		this.runRPC({		
			url: this.getRPCUrl('move'),
			/* I hitch to get this.loadOkHandler */
			load: function(response){
				success = this.doMoveProcessResponse(response, child, newParent, index) ;
			},
			sync: true,
			lock: [child, newParent],
			params: params
		});


		return success;
	},

	doMoveProcessResponse: function(response, child, newParent, index){

		if(!dojo.lang.isUndefined(response.error)){
			this.RPCErrorHandler("server", response.error);
			return false;
		}

		var args = [child, newParent, index];
		return dojo.widget.TreeLoadingController.prototype.doMove.apply(this, args);

	},


	doRemoveNode: function(node, callObj, callFunc){

		var params = {
			node: this.getInfo(node),
			tree: this.getInfo(node.tree)
		}

		this.runRPC({
				url: this.getRPCUrl('removeNode'),
				/* I hitch to get this.loadOkHandler */
				load: function(response){
					this.doRemoveNodeProcessResponse(response, node, callObj, callFunc) 
				},
				params: params,
				lock: [node]
		});

	},


	doRemoveNodeProcessResponse: function(response, node, callObj, callFunc){
		if(!dojo.lang.isUndefined(response.error)){
			this.RPCErrorHandler("server", response.error);
			return false;
		}

		if(!response){ return false; }

		if(response == true){
			/* change parent succeeded */
			var args = [ node, callObj, callFunc ];
			dojo.widget.TreeLoadingController.prototype.doRemoveNode.apply(this, args);

			return;
		}else if(dojo.lang.isObject(response)){
			dojo.raise(response.error);
		}else{
			dojo.raise("Invalid response "+response)
		}


	},



	// -----------------------------------------------------------------------------
	//                             Create node stuff
	// -----------------------------------------------------------------------------


	doCreateChild: function(parent, index, output, callObj, callFunc){

			var params = {
				tree: this.getInfo(parent.tree),
				parent: this.getInfo(parent),
				index: index,
				data: output
			}

			this.runRPC({
				url: this.getRPCUrl('createChild'),
				load: function(response) {
					// suggested data is dead, fresh data from server is used
					this.doCreateChildProcessResponse( response, parent, index, callObj, callFunc) 
				},
				params: params,
				lock: [parent]
			});

	},

	doCreateChildProcessResponse: function(response, parent, index, callObj, callFunc){

		if(!dojo.lang.isUndefined(response.error)){
			this.RPCErrorHandler("server",response.error);
			return false;
		}

		if(!dojo.lang.isObject(response)){
			dojo.raise("Invalid result "+response)
		}

		var args = [parent, index, response, callObj, callFunc];
		
		dojo.widget.TreeLoadingController.prototype.doCreateChild.apply(this, args);
	}
});
