/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.collections.Graph");
dojo.require("dojo.collections.Collections");

dojo.experimental("dojo.collections.Graph");

dojo.collections.Graph=function(nodes){
	function node(key, data, neighbors) {
		this.key=key;
		this.data=data;
		this.neighbors=neighbors||new adjacencyList();
		this.addDirected=function(){
			if (arguments[0].constructor==edgeToNeighbor){
				this.neighbors.add(arguments[0]);
			}else{
				var n=arguments[0];
				var cost=arguments[1]||0;
				this.neighbors.add(new edgeToNeighbor(n, cost));
			}
		}
	}
	function nodeList(){
		var d=new dojo.collections.Dictionary();
		function nodelistiterator(){
			var o=[] ;	//	Create an indexing array
			var e=d.getIterator();
			while(e.get()){
				o[o.length]=e.element;
			}

			var position=0;
			this.element=o[position]||null;
			this.atEnd=function(){
				return (position>=o.length);
			}
			this.get=function(){
				if(this.atEnd()){
					return null;		//	object
				}
				this.element=o[position++];
				return this.element;	//	object
			};
			this.map=function(/* function */fn, /* object? */scope){
				var s=scope||dj_global;
				if(Array.map){
					return Array.map(o,fn,s);	//	array
				}else{
					var arr=[];
					for(var i=0; i<o.length; i++){
						arr.push(fn.call(s,o[i]));
					}
					return arr;		//	array
				}
			};
			this.reset=function(){
				position=0;
				this.element=o[position];
			};
		}
		
		this.add=function(node){
			d.add(node.key, node);
		};
		this.clear=function(){
			d.clear();
		};
		this.containsKey=function(key){
			return d.containsKey(key);
		};
		this.getIterator=function(){
			return new nodelistiterator(this);
		};
		this.item=function(key){
			return d.item(key);
		};
		this.remove=function(node){
			d.remove(node.key);
		};
	}
	function edgeToNeighbor(node, cost){
		this.neighbor=node;
		this.cost=cost;
	}
	function adjacencyList(){
		var d=[];
		this.add=function(o){
			d.push(o);
		};
		this.item=function(i){
			return d[i];
		};
		this.getIterator=function(){
			return new dojo.collections.Iterator([].concat(d));
		};
	}

	this.nodes=nodes||new nodeList();
	this.count=this.nodes.count;
	this.clear=function(){
		this.nodes.clear();
		this.count=0;
	};
	this.addNode=function(){
		var n=arguments[0];
		if(arguments.length > 1){
			n=new node(arguments[0],arguments[1]);
		}
		if(!this.nodes.containsKey(n.key)){
			this.nodes.add(n);
			this.count++;
		}
	};
	this.addDirectedEdge=function(uKey, vKey, cost){
		var uNode,vNode;
		if(uKey.constructor!= node){
			uNode=this.nodes.item(uKey);
			vNode=this.nodes.item(vKey);
		}else{
			uNode=uKey;
			vNode=vKey;
		}
		var c=cost||0;
		uNode.addDirected(vNode,c);
	};
	this.addUndirectedEdge=function(uKey, vKey, cost){
		var uNode, vNode;
		if(uKey.constructor!=node){
			uNode=this.nodes.item(uKey);
			vNode=this.nodes.item(vKey);
		}else{
			uNode=uKey;
			vNode=vKey;
		}
		var c=cost||0;
		uNode.addDirected(vNode,c);
		vNode.addDirected(uNode,c);
	};
	this.contains=function(n){
		return this.nodes.containsKey(n.key);
	};
	this.containsKey=function(k){
		return this.nodes.containsKey(k);
	};
}
