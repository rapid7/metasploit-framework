/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.behavior");
dojo.require("dojo.event.*");

dojo.require("dojo.experimental");
dojo.experimental("dojo.behavior");

dojo.behavior = new function(){
	function arrIn(obj, name){
		if(!obj[name]){ obj[name] = []; }
		return obj[name];
	}

	function forIn(obj, scope, func){
		var tmpObj = {};
		for(var x in obj){
			if(typeof tmpObj[x] == "undefined"){
				if(!func){
					scope(obj[x], x);
				}else{
					func.call(scope, obj[x], x);
				}
			}
		}
	}

	// FIXME: need a better test so we don't exclude nightly Safari's!
	this.behaviors = {};
	this.add = function(behaviorObj){
		/*	behavior objects are specified in the following format:
		 *
		 *	{ 
		 *	 	"#id": {
		 *			"found": function(element){
		 *				// ...
		 *			},
		 *
		 *			"onblah": {targetObj: foo, targetFunc: "bar"},
		 *
		 *			"onblarg": "/foo/bar/baz/blarg",
		 *
		 *			"onevent": function(evt){
		 *			},
		 *
		 *			"onotherevent: function(evt){
		 *				// ...
		 *			}
		 *		},
		 *
		 *		"#id2": {
		 *			// ...
		 *		},
		 *
		 *		"#id3": function(element){
		 *			// ...
		 *		},
		 *
		 *		// publish the match on a topic
		 *		"#id4": "/found/topic/name",
		 *
		 *		// match all direct descendants
		 *		"#id4 > *": function(element){
		 *			// ...
		 *		},
		 *
		 *		// match the first child node that's an element
		 *		"#id4 > @firstElement": { ... },
		 *
		 *		// match the last child node that's an element
		 *		"#id4 > @lastElement":  { ... },
		 *
		 *		// all elements of type tagname
		 *		"tagname": {
		 *			// ...
		 *		},
		 *
		 *		// maps to roughly:
		 *		//	dojo.lang.forEach(body.getElementsByTagName("tagname1"), function(node){
		 *		//		dojo.lang.forEach(node.getElementsByTagName("tagname2"), function(node2){
		 *		//			dojo.lang.forEach(node2.getElementsByTagName("tagname3", function(node3){
		 *		//				// apply rules
		 *		//			});
		 *		//		});
		 *		//	});
		 *		"tagname1 tagname2 tagname3": {
		 *			// ...
		 *		},
		 *
		 *		".classname": {
		 *			// ...
		 *		},
		 *
		 *		"tagname.classname": {
		 *			// ...
		 *		},
		 *	}
		 *
		 *	The "found" method is a generalized handler that's called as soon
		 *	as the node matches the selector. Rules for values that follow also
		 *	apply to the "found" key.
		 *	
		 *	The "on*" handlers are attached with dojo.event.connect(). If the
		 *	value is not a function but is rather an object, it's assumed to be
		 *	the "other half" of a dojo.event.kwConnect() argument object. It
		 *	may contain any/all properties of such a connection modifier save
		 *	for the sourceObj and sourceFunc properties which are filled in by
		 *	the system automatically. If a string is instead encountered, the
		 *	node publishes the specified event on the topic contained in the
		 *	string value.
		 *
		 *	If the value corresponding to the ID key is a function and not a
		 *	list, it's treated as though it was the value of "found".
		 *
		 */

		var tmpObj = {};
		forIn(behaviorObj, this, function(behavior, name){
			var tBehavior = arrIn(this.behaviors, name);
			if((dojo.lang.isString(behavior))||(dojo.lang.isFunction(behavior))){
				behavior = { found: behavior };
			}
			forIn(behavior, function(rule, ruleName){
				arrIn(tBehavior, ruleName).push(rule);
			});
		});
	}

	this.apply = function(){
		dojo.profile.start("dojo.behavior.apply");
		var r = dojo.render.html;
		// note, we apply one way for fast queries and one way for slow
		// iteration. So be it.
		var safariGoodEnough = (!r.safari);
		if(r.safari){
			// Anything over release #420 should work the fast way
			var uas = r.UA.split("AppleWebKit/")[1];
			if(parseInt(uas.match(/[0-9.]{3,}/)) >= 420){
				safariGoodEnough = true;
			}
		}
		if((dj_undef("behaviorFastParse", djConfig) ? (safariGoodEnough) : djConfig["behaviorFastParse"])){
			this.applyFast();
		}else{
			this.applySlow();
		}
		dojo.profile.end("dojo.behavior.apply");
	}

	this.matchCache = {};

	this.elementsById = function(id, handleRemoved){
		var removed = [];
		var added = [];
		arrIn(this.matchCache, id);
		if(handleRemoved){
			var nodes = this.matchCache[id];
			for(var x=0; x<nodes.length; x++){
				if(nodes[x].id != ""){
					removed.push(nodes[x]);
					nodes.splice(x, 1);
					x--;
				}
			}
		}
		var tElem = dojo.byId(id);
		while(tElem){
			if(!tElem["idcached"]){
				added.push(tElem);
			}
			tElem.id = "";
			tElem = dojo.byId(id);
		}
		this.matchCache[id] = this.matchCache[id].concat(added);
		dojo.lang.forEach(this.matchCache[id], function(node){
			node.id = id;
			node.idcached = true;
		});
		return { "removed": removed, "added": added, "match": this.matchCache[id] };
	}

	this.applyToNode = function(node, action, ruleSetName){
		if(typeof action == "string"){
			dojo.event.topic.registerPublisher(action, node, ruleSetName);
		}else if(typeof action == "function"){
			if(ruleSetName == "found"){
				action(node);
			}else{
				dojo.event.connect(node, ruleSetName, action);
			}
		}else{
			action.srcObj = node;
			action.srcFunc = ruleSetName;
			dojo.event.kwConnect(action);
		}
	}

	this.applyFast = function(){
		dojo.profile.start("dojo.behavior.applyFast");
		// fast DOM queries...wheeee!
		forIn(this.behaviors, function(tBehavior, id){
			var elems = dojo.behavior.elementsById(id);
			dojo.lang.forEach(elems.added, 
				function(elem){
					forIn(tBehavior, function(ruleSet, ruleSetName){
						if(dojo.lang.isArray(ruleSet)){
							dojo.lang.forEach(ruleSet, function(action){
								dojo.behavior.applyToNode(elem, action, ruleSetName);
							});
						}
					});
				}
			);
		});
		dojo.profile.end("dojo.behavior.applyFast");
	}
	
	this.applySlow = function(){
		// iterate. Ugg.
		dojo.profile.start("dojo.behavior.applySlow");
		var all = document.getElementsByTagName("*");
		var allLen = all.length;
		for(var x=0; x<allLen; x++){
			var elem = all[x];
			if((elem.id)&&(!elem["behaviorAdded"])&&(this.behaviors[elem.id])){
				elem["behaviorAdded"] = true;
				forIn(this.behaviors[elem.id], function(ruleSet, ruleSetName){
					if(dojo.lang.isArray(ruleSet)){
						dojo.lang.forEach(ruleSet, function(action){
							dojo.behavior.applyToNode(elem, action, ruleSetName);
						});
					}
				});
			}
		}
		dojo.profile.end("dojo.behavior.applySlow");
	}
}

dojo.addOnLoad(dojo.behavior, "apply");
