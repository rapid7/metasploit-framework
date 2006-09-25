/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.json");
dojo.require("dojo.lang.func");
dojo.require("dojo.string.extras");
dojo.require("dojo.AdapterRegistry");

dojo.json = {
	jsonRegistry: new dojo.AdapterRegistry(),

	register: function(name, check, wrap, /*optional*/ override){
		/***

			Register a JSON serialization function.	 JSON serialization 
			functions should take one argument and return an object
			suitable for JSON serialization:

			- string
			- number
			- boolean
			- undefined
			- object
				- null
				- Array-like (length property that is a number)
				- Objects with a "json" method will have this method called
				- Any other object will be used as {key:value, ...} pairs
			
			If override is given, it is used as the highest priority
			JSON serialization, otherwise it will be used as the lowest.
		***/

		dojo.json.jsonRegistry.register(name, check, wrap, override);
	},

	evalJson: function(/* jsonString */ json){
		// FIXME: should this accept mozilla's optional second arg?
		try {
			return eval("(" + json + ")");
		}catch(e){
			dojo.debug(e);
			return json;
		}
	},

	evalJSON: function (json) {
		dojo.deprecated("dojo.json.evalJSON", "use dojo.json.evalJson", "0.4");
		return this.evalJson(json);
	},

	serialize: function(o){
		/***
			Create a JSON serialization of an object, note that this doesn't
			check for infinite recursion, so don't do that!
		***/

		var objtype = typeof(o);
		if(objtype == "undefined"){
			return "undefined";
		}else if((objtype == "number")||(objtype == "boolean")){
			return o + "";
		}else if(o === null){
			return "null";
		}
		if (objtype == "string") { return dojo.string.escapeString(o); }
		// recurse
		var me = arguments.callee;
		// short-circuit for objects that support "json" serialization
		// if they return "self" then just pass-through...
		var newObj;
		if(typeof(o.__json__) == "function"){
			newObj = o.__json__();
			if(o !== newObj){
				return me(newObj);
			}
		}
		if(typeof(o.json) == "function"){
			newObj = o.json();
			if (o !== newObj) {
				return me(newObj);
			}
		}
		// array
		if(objtype != "function" && typeof(o.length) == "number"){
			var res = [];
			for(var i = 0; i < o.length; i++){
				var val = me(o[i]);
				if(typeof(val) != "string"){
					val = "undefined";
				}
				res.push(val);
			}
			return "[" + res.join(",") + "]";
		}
		// look in the registry
		try {
			window.o = o;
			newObj = dojo.json.jsonRegistry.match(o);
			return me(newObj);
		}catch(e){
			// dojo.debug(e);
		}
		// it's a function with no adapter, bad
		if(objtype == "function"){
			return null;
		}
		// generic object code path
		res = [];
		for (var k in o){
			var useKey;
			if (typeof(k) == "number"){
				useKey = '"' + k + '"';
			}else if (typeof(k) == "string"){
				useKey = dojo.string.escapeString(k);
			}else{
				// skip non-string or number keys
				continue;
			}
			val = me(o[k]);
			if(typeof(val) != "string"){
				// skip non-serializable values
				continue;
			}
			res.push(useKey + ":" + val);
		}
		return "{" + res.join(",") + "}";
	}
};
