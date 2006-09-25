/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.collections.Collections");

dojo.collections={Collections:true};
dojo.collections.DictionaryEntry=function(/* string */k, /* object */v){
	//	summary
	//	return an object of type dojo.collections.DictionaryEntry
	this.key=k;
	this.value=v;
	this.valueOf=function(){ 
		return this.value; 	//	object
	};
	this.toString=function(){ 
		return String(this.value);	//	string 
	};
}

/*	Iterators
 *	The collections.Iterators (Iterator and DictionaryIterator) are built to
 *	work with the Collections included in this namespace.  However, they *can*
 *	be used with arrays and objects, respectively, should one choose to do so.
 */
dojo.collections.Iterator=function(/* array */arr){
	//	summary
	//	return an object of type dojo.collections.Iterator
	var a=arr;
	var position=0;
	this.element=a[position]||null;
	this.atEnd=function(){
		//	summary
		//	Test to see if the internal cursor has reached the end of the internal collection.
		return (position>=a.length);	//	bool
	};
	this.get=function(){
		//	summary
		//	Test to see if the internal cursor has reached the end of the internal collection.
		if(this.atEnd()){
			return null;		//	object
		}
		this.element=a[position++];
		return this.element;	//	object
	};
	this.map=function(/* function */fn, /* object? */scope){
		//	summary
		//	Functional iteration with optional scope.
		var s=scope||dj_global;
		if(Array.map){
			return Array.map(a,fn,s);	//	array
		}else{
			var arr=[];
			for(var i=0; i<a.length; i++){
				arr.push(fn.call(s,a[i]));
			}
			return arr;		//	array
		}
	};
	this.reset=function(){
		//	summary
		//	reset the internal cursor.
		position=0;
		this.element=a[position];
	};
}

/*	Notes:
 *	The DictionaryIterator no longer supports a key and value property;
 *	the reality is that you can use this to iterate over a JS object
 *	being used as a hashtable.
 */
dojo.collections.DictionaryIterator=function(/* object */obj){
	//	summary
	//	return an object of type dojo.collections.DictionaryIterator
	var a=[];	//	Create an indexing array
	var testObject={};
	for(var p in obj){
		if(!testObject[p]){
			a.push(obj[p]);	//	fill it up
		}
	}
	var position=0;
	this.element=a[position]||null;
	this.atEnd=function(){
		//	summary
		//	Test to see if the internal cursor has reached the end of the internal collection.
		return (position>=a.length);	//	bool
	};
	this.get=function(){
		//	summary
		//	Test to see if the internal cursor has reached the end of the internal collection.
		if(this.atEnd()){
			return null;		//	object
		}
		this.element=a[position++];
		return this.element;	//	object
	};
	this.map=function(/* function */fn, /* object? */scope){
		//	summary
		//	Functional iteration with optional scope.
		var s=scope||dj_global;
		if(Array.map){
			return Array.map(a,fn,s);	//	array
		}else{
			var arr=[];
			for(var i=0; i<a.length; i++){
				arr.push(fn.call(s,a[i]));
			}
			return arr;		//	array
		}
	};
	this.reset=function() { 
		//	summary
		//	reset the internal cursor.
		position=0; 
		this.element=a[position];
	};
};
