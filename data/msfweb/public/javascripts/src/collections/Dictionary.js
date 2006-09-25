/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.collections.Dictionary");
dojo.require("dojo.collections.Collections");

dojo.collections.Dictionary=function(/* dojo.collections.Dictionary? */dictionary){
	//	summary
	//	Returns an object of type dojo.collections.Dictionary
	var items={};
	this.count=0;

	//	comparator for property addition and access.
	var testObject={};

	this.add=function(/* string */k, /* object */v){
		//	summary
		//	Add a new item to the Dictionary.
		var b=(k in items);
		items[k]=new dojo.collections.DictionaryEntry(k,v);
		if(!b){
			this.count++;
		}
	};
	this.clear=function(){
		//	summary
		//	Clears the internal dictionary.
		items={};
		this.count=0;
	};
	this.clone=function(){
		//	summary
		//	Returns a new instance of dojo.collections.Dictionary; note the the dictionary is a clone but items might not be.
		return new dojo.collections.Dictionary(this);	//	dojo.collections.Dictionary
	};
	this.contains=this.containsKey=function(/* string */k){
		//	summary
		//	Check to see if the dictionary has an entry at key "k".
		if(testObject[k]){
			return false;			// bool
		}
		return (items[k]!=null);	//	bool
	};
	this.containsValue=function(/* object */v){
		//	summary
		//	Check to see if the dictionary has an entry with value "v".
		var e=this.getIterator();
		while(e.get()){
			if(e.element.value==v){
				return true;	//	bool
			}
		}
		return false;	//	bool
	};
	this.entry=function(/* string */k){
		//	summary
		//	Accessor method; similar to dojo.collections.Dictionary.item but returns the actual Entry object.
		return items[k];	//	dojo.collections.DictionaryEntry
	};
	this.forEach=function(/* function */ fn, /* object? */ scope){
		//	summary
		//	functional iterator, following the mozilla spec.
		var a=[];	//	Create an indexing array
		for(var p in items) {
			if(!testObject[p]){
				a.push(items[p]);	//	fill it up
			}
		}
		var s=scope||dj_global;
		if(Array.forEach){
			Array.forEach(a, fn, s);
		}else{
			for(var i=0; i<a.length; i++){
				fn.call(s, a[i], i, a);
			}
		}
	};
	this.getKeyList=function(){
		//	summary
		//	Returns an array of the keys in the dictionary.
		return (this.getIterator()).map(function(entry){ 
			return entry.key; 
		});	//	array
	};
	this.getValueList=function(){
		//	summary
		//	Returns an array of the values in the dictionary.
		return (this.getIterator()).map(function(entry){ 
			return entry.value; 
		});	//	array
	};
	this.item=function(/* string */k){
		//	summary
		//	Accessor method.
		if(k in items){
			return items[k].valueOf();	//	object
		}
		return undefined;	//	object
	};
	this.getIterator=function(){
		//	summary
		//	Gets a dojo.collections.DictionaryIterator for iteration purposes.
		return new dojo.collections.DictionaryIterator(items);	//	dojo.collections.DictionaryIterator
	};
	this.remove=function(/* string */k){
		//	summary
		//	Removes the item at k from the internal collection.
		if(k in items && !testObject[k]){
			delete items[k];
			this.count--;
			return true;	//	bool
		}
		return false;	//	bool
	};

	if (dictionary){
		var e=dictionary.getIterator();
		while(e.get()) {
			 this.add(e.element.key, e.element.value);
		}
	}
};
