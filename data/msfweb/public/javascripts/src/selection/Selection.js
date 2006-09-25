/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.selection.Selection");
dojo.require("dojo.lang.array");
dojo.require("dojo.lang.func");
dojo.require("dojo.math");

dojo.selection.Selection = function(items, isCollection) {
	this.items = [];
	this.selection = [];
	this._pivotItems = [];
	this.clearItems();

	if(items) {
		if(isCollection) {
			this.setItemsCollection(items);
		} else {
			this.setItems(items);
		}
	}
}
dojo.lang.extend(dojo.selection.Selection, {
	items: null, // items to select from, order matters for growable selections

	selection: null, // items selected, aren't stored in order (see sorted())
	lastSelected: null, // last item selected

	allowImplicit: true, // if true, grow selection will start from 0th item when nothing is selected
	length: 0, // number of *selected* items

	// if true, the selection is treated as an in-order and can grow by ranges, not just by single item
	isGrowable: true,

	_pivotItems: null, // stack of pivot items
	_pivotItem: null, // item we grow selections from, top of stack

	// event handlers
	onSelect: function(item) {},
	onDeselect: function(item) {},
	onSelectChange: function(item, selected) {},

	_find: function(item, inSelection) {
		if(inSelection) {
			return dojo.lang.find(item, this.selection);
		} else {
			return dojo.lang.find(item, this.items);
		}
	},

	isSelectable: function(item) {
		// user-customizable, will filter items through this
		return true;
	},

	setItems: function(/* ... */) {
		this.clearItems();
		this.addItems.call(this, arguments);
	},

	// this is in case you have an active collection array-like object
	// (i.e. getElementsByTagName collection) that manages its own order
	// and item list
	setItemsCollection: function(collection) {
		this.items = collection;
	},

	addItems: function(/* ... */) {
		var args = dojo.lang.unnest(arguments);
		for(var i = 0; i < args.length; i++) {
			this.items.push(args[i]);
		}
	},

	addItemsAt: function(item, before /* ... */) {
		if(this.items.length == 0) { // work for empy case
			return this.addItems(dojo.lang.toArray(arguments, 2));
		}

		if(!this.isItem(item)) {
			item = this.items[item];
		}
		if(!item) { throw new Error("addItemsAt: item doesn't exist"); }
		var idx = this._find(item);
		if(idx > 0 && before) { idx--; }
		for(var i = 2; i < arguments.length; i++) {
			if(!this.isItem(arguments[i])) {
				this.items.splice(idx++, 0, arguments[i]);
			}
		}
	},

	removeItem: function(item) {
		// remove item
		var idx = this._find(item);
		if(idx > -1) {
			this.items.splice(idx, 1);
		}
		// remove from selection
		// FIXME: do we call deselect? I don't think so because this isn't how
		// you usually want to deselect an item. For example, if you deleted an
		// item, you don't really want to deselect it -- you want it gone. -DS
		idx = this._find(item, true);
		if(idx > -1) {
			this.selection.splice(idx, 1);
		}
	},

	clearItems: function() {
		this.items = [];
		this.deselectAll();
	},

	isItem: function(item) {
		return this._find(item) > -1;
	},

	isSelected: function(item) {
		return this._find(item, true) > -1;
	},

	/**
	 * allows you to filter item in or out of the selection
	 * depending on the current selection and action to be taken
	**/
	selectFilter: function(item, selection, add, grow) {
		return true;
	},

	/**
	 * update -- manages selections, most selecting should be done here
	 *  item => item which may be added/grown to/only selected/deselected
	 *  add => behaves like ctrl in windows selection world
	 *  grow => behaves like shift
	 *  noToggle => if true, don't toggle selection on item
	**/
	update: function(item, add, grow, noToggle) {
		if(!this.isItem(item)) { return false; }

		if(this.isGrowable && grow) {
			if(!this.isSelected(item)
				&& this.selectFilter(item, this.selection, false, true)) {
				this.grow(item);
				this.lastSelected = item;
			}
		} else if(add) {
			if(this.selectFilter(item, this.selection, true, false)) {
				if(noToggle) {
					if(this.select(item)) {
						this.lastSelected = item;
					}
				} else if(this.toggleSelected(item)) {
					this.lastSelected = item;
				}
			}
		} else {
			this.deselectAll();
			this.select(item);
		}

		this.length = this.selection.length;
	},

	/**
	 * Grow a selection.
	 *  toItem => which item to grow selection to
	 *  fromItem => which item to start the growth from (it won't be selected)
	 *
	 * Any items in (fromItem, lastSelected] that aren't part of
	 * (fromItem, toItem] will be deselected
	**/
	grow: function(toItem, fromItem) {
		if(!this.isGrowable) { return; }

		if(arguments.length == 1) {
			fromItem = this._pivotItem;
			if(!fromItem && this.allowImplicit) {
				fromItem = this.items[0];
			}
		}
		if(!toItem || !fromItem) { return false; }

		var fromIdx = this._find(fromItem);

		// get items to deselect (fromItem, lastSelected]
		var toDeselect = {};
		var lastIdx = -1;
		if(this.lastSelected) {
			lastIdx = this._find(this.lastSelected);
			var step = fromIdx < lastIdx ? -1 : 1;
			var range = dojo.math.range(lastIdx, fromIdx, step);
			for(var i = 0; i < range.length; i++) {
				toDeselect[range[i]] = true;
			}
		}

		// add selection (fromItem, toItem]
		var toIdx = this._find(toItem);
		var step = fromIdx < toIdx ? -1 : 1;
		var shrink = lastIdx >= 0 && step == 1 ? lastIdx < toIdx : lastIdx > toIdx;
		var range = dojo.math.range(toIdx, fromIdx, step);
		if(range.length) {
			for(var i = range.length-1; i >= 0; i--) {
				var item = this.items[range[i]];
				if(this.selectFilter(item, this.selection, false, true)) {
					if(this.select(item, true) || shrink) {
						this.lastSelected = item;
					}
					if(range[i] in toDeselect) {
						delete toDeselect[range[i]];
					}
				}
			}
		} else {
			this.lastSelected = fromItem;
		}

		// now deselect...
		for(var i in toDeselect) {
			if(this.items[i] == this.lastSelected) {
				//dojo.debug("oops!");
			}
			this.deselect(this.items[i]);
		}

		// make sure everything is all kosher after selections+deselections
		this._updatePivot();
	},

	/**
	 * Grow selection upwards one item from lastSelected
	**/
	growUp: function() {
		if(!this.isGrowable) { return; }

		var idx = this._find(this.lastSelected) - 1;
		while(idx >= 0) {
			if(this.selectFilter(this.items[idx], this.selection, false, true)) {
				this.grow(this.items[idx]);
				break;
			}
			idx--;
		}
	},

	/**
	 * Grow selection downwards one item from lastSelected
	**/
	growDown: function() {
		if(!this.isGrowable) { return; }

		var idx = this._find(this.lastSelected);
		if(idx < 0 && this.allowImplicit) {
			this.select(this.items[0]);
			idx = 0;
		}
		idx++;
		while(idx > 0 && idx < this.items.length) {
			if(this.selectFilter(this.items[idx], this.selection, false, true)) {
				this.grow(this.items[idx]);
				break;
			}
			idx++;
		}
	},

	toggleSelected: function(item, noPivot) {
		if(this.isItem(item)) {
			if(this.select(item, noPivot)) { return 1; }
			if(this.deselect(item)) { return -1; }
		}
		return 0;
	},

	select: function(item, noPivot) {
		if(this.isItem(item) && !this.isSelected(item)
			&& this.isSelectable(item)) {
			this.selection.push(item);
			this.lastSelected = item;
			this.onSelect(item);
			this.onSelectChange(item, true);
			if(!noPivot) {
				this._addPivot(item);
			}
			return true;
		}
		return false;
	},

	deselect: function(item) {
		var idx = this._find(item, true);
		if(idx > -1) {
			this.selection.splice(idx, 1);
			this.onDeselect(item);
			this.onSelectChange(item, false);
			if(item == this.lastSelected) {
				this.lastSelected = null;
			}

			this._removePivot(item);

			return true;
		}
		return false;
	},

	selectAll: function() {
		for(var i = 0; i < this.items.length; i++) {
			this.select(this.items[i]);
		}
	},

	deselectAll: function() {
		while(this.selection && this.selection.length) {
			this.deselect(this.selection[0]);
		}
	},

	selectNext: function() {
		var idx = this._find(this.lastSelected);
		while(idx > -1 && ++idx < this.items.length) {
			if(this.isSelectable(this.items[idx])) {
				this.deselectAll();
				this.select(this.items[idx]);
				return true;
			}
		}
		return false;
	},

	selectPrevious: function() {
		//debugger;
		var idx = this._find(this.lastSelected);
		while(idx-- > 0) {
			if(this.isSelectable(this.items[idx])) {
				this.deselectAll();
				this.select(this.items[idx]);
				return true;
			}
		}
		return false;
	},

	// select first selectable item
	selectFirst: function() {
		this.deselectAll();
		var idx = 0;
		while(this.items[idx] && !this.select(this.items[idx])) {
			idx++;
		}
		return this.items[idx] ? true : false;
	},

	// select last selectable item
	selectLast: function() {
		this.deselectAll();
		var idx = this.items.length-1;
		while(this.items[idx] && !this.select(this.items[idx])) {
			idx--;
		}
		return this.items[idx] ? true : false;
	},

	_addPivot: function(item, andClear) {
		this._pivotItem = item;
		if(andClear) {
			this._pivotItems = [item];
		} else {
			this._pivotItems.push(item);
		}
	},

	_removePivot: function(item) {
		var i = dojo.lang.find(item, this._pivotItems);
		if(i > -1) {
			this._pivotItems.splice(i, 1);
			this._pivotItem = this._pivotItems[this._pivotItems.length-1];
		}

		this._updatePivot();
	},

	_updatePivot: function() {
		if(this._pivotItems.length == 0) {
			if(this.lastSelected) {
				this._addPivot(this.lastSelected);
			}
		}
	},

	sorted: function() {
		return dojo.lang.toArray(this.selection).sort(
			dojo.lang.hitch(this, function(a, b) {
				var A = this._find(a), B = this._find(b);
				if(A > B) {
					return 1;
				} else if(A < B) {
					return -1;
				} else {
					return 0;
				}
			})
		);
	},

	// remove any items from the selection that are no longer in this.items
	updateSelected: function() {
		for(var i = 0; i < this.selection.length; i++) {
			if(this._find(this.selection[i]) < 0) {
				var removed = this.selection.splice(i, 1);

				this._removePivot(removed[0]);
			}
		}

		this.length = this.selection.length;
	}
});
