/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.collections.SkipList");
dojo.require("dojo.collections.Collections");
dojo.require("dojo.experimental");

dojo.experimental("dojo.collections.SkipList");

dojo.collections.SkipList = function(){
	function node(height, val){
		this.value = val;
		this.height = height;
		this.nodes = new nodeList(height);
		this.compare = function(val){
			if (this.value > val) return 1;
			if (this.value < val) return -1;
			return 0;
		}
		this.incrementHeight = function(){
			this.nodes.incrementHeight();
			this.height++;
		};
		this.decrementHeight = function(){
			this.nodes.decrementHeight();
			this.height--;
		};
	}
	function nodeList(height){
		var arr = [];
		this.height = height;
		for (var i = 0; i < height; i++) arr[i] = null;
		this.item = function(i){
			return arr[i];
		};
		this.incrementHeight = function(){
			this.height++;
			arr[this.height] = null;
		};
		this.decrementHeight = function(){
			arr.splice(arr.length - 1, 1);
			this.height--;
		};
	}
	function iterator(list){
		this.current = list.head;
		this.atEnd = false;
		this.moveNext = function(){
			if (this.atEnd) return !this.atEnd;
			this.current = this.current.nodes[0];
			this.atEnd = (this.current == null);
			return !this.atEnd;
		};
		this.reset = function(){
			this.current = null;
		};
	}

	function chooseRandomHeight(max){
		var level = 1;
		while (Math.random() < PROB && level < max) level++;
		return level;
	}

	var PROB = 0.5;
	var comparisons = 0;

	this.head = new node(1);
	this.count = 0;
	this.add = function(val){
		var updates = [];
		var current = this.head;
		for (var i = this.head.height; i >= 0; i--){
			if (!(current.nodes[i] != null && current.nodes[i].compare(val) < 0)) comparisons++;
			while (current.nodes[i] != null && current.nodes[i].compare(val) < 0){
				current = current.nodes[i];
				comparisons++;
			}
			updates[i] = current;
		}
		if (current.nodes[0] != null && current.nodes[0].compare(val) == 0) return;
		var n = new node(val, chooseRandomHeight(this.head.height + 1));
		this.count++;
		if (n.height > this.head.height){
			this.head.incrementHeight();
			this.head.nodes[this.head.height - 1] = n;
		}
		for (i = 0; i < n.height; i++){
			if (i < updates.length) {
				n.nodes[i] = updates[i].nodes[i];
				updates[i].nodes[i] = n;
			}
		}
	};
	
	this.contains = function(val){
		var current = this.head;
		var i;
		for (i = this.head.height - 1; i >= 0; i--) {
			while (current.item(i) != null) {
				comparisons++;
				var result = current.nodes[i].compare(val);
				if (result == 0) return true;
				else if (result < 0) current = current.nodes[i];
				else break;
			}
		}
		return false;
	};
	this.getIterator = function(){
		return new iterator(this);
	};

	this.remove = function(val){
		var updates = [];
		var current = this.head;
		for (var i = this.head.height - 1; i >= 0; i--){
			if (!(current.nodes[i] != null && current.nodes[i].compare(val) < 0)) comparisons++;
			while (current.nodes[i] != null && current.nodes[i].compare(val) < 0) {
				current = current.nodes[i];
				comparisons++;
			}
			updates[i] = current;
		}
		
		current = current.nodes[0];
		if (current != null && current.compare(val) == 0){
			this.count--;
			for (var i = 0; i < this.head.height; i++){
				if (updates[i].nodes[i] != current) break;
				else updates[i].nodes[i] = current.nodes[i];
			}
			if (this.head.nodes[this.head.height - 1] == null) this.head.decrementHeight();
		}
	};
	this.resetComparisons = function(){ 
		comparisons = 0; 
	};
}
