/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/**
 * Additional tree utils
 *
 */
dojo.provide("dojo.widget.TreeControllerExtension");


dojo.widget.TreeControllerExtension = function() { }

dojo.lang.extend(dojo.widget.TreeControllerExtension, {

	saveExpandedIndices: function(node, field) {
		var obj = {};

		for(var i=0; i<node.children.length; i++) {
			if (node.children[i].isExpanded) {
				var key = dojo.lang.isUndefined(field) ? i : node.children[i][field];
				obj[key] = this.saveExpandedIndices(node.children[i], field);
			}
		}

		return obj;
	},


	restoreExpandedIndices: function(node, savedIndices, field) {
		var _this = this;

		var handler = function(node, savedIndices) {
			this.node = node; //.children[i];
			this.savedIndices = savedIndices; //[i];
			// recursively read next savedIndices level and apply to opened node
			this.process = function() {
				//dojo.debug("Callback applied for "+this.node);
				_this.restoreExpandedIndices(this.node, this.savedIndices, field);
			};
		}


		for(var i=0; i<node.children.length; i++) {
			var child = node.children[i];

			var found = false;
			var key = -1;

			//dojo.debug("Check "+child)
			// process field set case
			if (dojo.lang.isUndefined(field) && savedIndices[i]) {
				found = true;
				key = i;
			}

			// process case when field is not set
			if (field) {
				for(var key in savedIndices) {
					//dojo.debug("Compare "+key+" "+child[field])
					if (key == child[field]) {
						found = true;
						break;
					}
				}
			}

			// if we found anything - expand it
			if (found) {
				//dojo.debug("Found at "+key)
				var h = new handler(child, savedIndices[key]);
				_this.expand(child, false, h, h.process);
			} else if (child.isExpanded) { // not found, so collapse
				//dojo.debug("Collapsing all descendants "+node.children[i])
				dojo.lang.forEach(child.getDescendants(), function(elem) { _this.collapse(elem); });
				//this.collapse(node.children[i]);
			}

		}


	}

});





