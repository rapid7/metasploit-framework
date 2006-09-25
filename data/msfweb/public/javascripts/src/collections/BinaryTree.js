/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.collections.BinaryTree");
dojo.require("dojo.collections.Collections");
dojo.require("dojo.experimental");

dojo.experimental("dojo.collections.BinaryTree");

dojo.collections.BinaryTree=function(data){
	function node(data, rnode, lnode){
		this.value=data||null;
		this.right=rnode||null;
		this.left=lnode||null;
		this.clone=function(){
			var c=new node();
			if (this.value.value) c.value=this.value.clone();
			else c.value=this.value;
			if (this.left) c.left=this.left.clone();
			if (this.right) c.right=this.right.clone();
		}
		this.compare=function(n){
			if (this.value > n.value) return 1;
			if (this.value < n.value) return -1;
			return 0;
		}
		this.compareData=function(d){
			if (this.value > d) return 1;
			if (this.value < d) return -1;
			return 0;
		}
	}

	function inorderTraversalBuildup(current, a){
		if (current){
			inorderTraversalBuildup(current.left, a);
			a.add(current);
			inorderTraversalBuildup(current.right, a);
		}
	}

	function preorderTraversal(current, sep){
		var s="";
		if (current){
			s=current.value.toString() + sep;
			s += preorderTraversal(current.left, sep);
			s += preorderTraversal(current.right, sep);
		}
		return s;
	}
	function inorderTraversal(current, sep){
		var s="";
		if (current){
			s=inorderTraversal(current.left, sep);
			s += current.value.toString() + sep;
			s += inorderTraversal(current.right, sep);
		}
		return s;
	}
	function postorderTraversal(current, sep){
		var s="";
		if (current){
			s=postorderTraversal(current.left, sep);
			s += postorderTraversal(current.right, sep);
			s += current.value.toString() + sep;
		}
		return s;
	}
	
	function searchHelper(current, data){
		if (!current) return null;
		var i=current.compareData(data);
		if (i==0) return current;
		if (i>0) return searchHelper(current.left, data);
		else return searchHelper(current.right, data);
	}

	this.add=function(data){
		var n=new node(data);
		var i;
		var current=root;
		var parent=null;
		while (current){
			i=current.compare(n);
			if (i == 0) return;
			parent=current;
			if (i > 0) current=current.left;
			else current=current.right;
		}
		this.count++;
		if (!parent) root=n;
		else {
			i=parent.compare(n);
			if (i > 0) parent.left=n;
			else parent.right=n;
		}
	};
	this.clear=function(){
		root=null;
		this.count=0;
	};
	this.clone=function(){
		var c=new dojo.collections.BinaryTree();
		c.root=root.clone();
		c.count=this.count;
		return c;
	};
	this.contains=function(data){
		return this.search(data) != null;
	};
	this.deleteData=function(data){
		var current=root;
		var parent=null;
		var i=current.compareData(data);
		while (i != 0 && current != null){
			if (i > 0){
				parent=current;
				current=current.left;
			} else if (i < 0) {
				parent=current;
				current=current.right;
			}
			i=current.compareData(data);
		}
		if (!current) return;
		this.count--;
		if (!current.right) {
			if (!parent) root=current.left;
			else {
				i=parent.compare(current);
				if (i > 0) parent.left=current.left;
				else if (i < 0) parent.right=current.left;
			}
		} else if (!current.right.left){
			if (!parent) root=current.right;
			else {
				i=parent.compare(current);
				if (i > 0) parent.left=current.right;
				else if (i < 0) parent.right=current.right;
			}
		} else {
			var leftmost=current.right.left;
			var lmParent=current.right;
			while (leftmost.left != null){
				lmParent=leftmost;
				leftmost=leftmost.left;
			}
			lmParent.left=leftmost.right;
			leftmost.left=current.left;
			leftmost.right=current.right;
			if (!parent) root=leftmost;
			else {
				i=parent.compare(current);
				if (i > 0) parent.left=leftmost;
				else if (i < 0) parent.right=leftmost;
			}
		}
	};
	this.getIterator=function(){
		var a=[];
		inorderTraversalBuildup(root, a);
		return new dojo.collections.Iterator(a);
	};
	this.search=function(data){
		return searchHelper(root, data);
	};
	this.toString=function(order, sep){
		if (!order) var order=dojo.collections.BinaryTree.TraversalMethods.Inorder;
		if (!sep) var sep=" ";
		var s="";
		switch (order){
			case dojo.collections.BinaryTree.TraversalMethods.Preorder:
				s=preorderTraversal(root, sep);
				break;
			case dojo.collections.BinaryTree.TraversalMethods.Inorder:
				s=inorderTraversal(root, sep);
				break;
			case dojo.collections.BinaryTree.TraversalMethods.Postorder:
				s=postorderTraversal(root, sep);
				break;
		};
		if (s.length == 0) return "";
		else return s.substring(0, s.length - sep.length);
	};

	this.count=0;
	var root=this.root=null;
	if (data) {
		this.add(data);
	}
}
dojo.collections.BinaryTree.TraversalMethods={
	Preorder : 0,
	Inorder : 1,
	Postorder : 2
};
