/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.event");

dojo.require("dojo.lang.array");
dojo.require("dojo.lang.extras");
dojo.require("dojo.lang.func");

dojo.event = new function(){
	this.canTimeout = dojo.lang.isFunction(dj_global["setTimeout"])||dojo.lang.isAlien(dj_global["setTimeout"]);

	// FIXME: where should we put this method (not here!)?
	function interpolateArgs(args, searchForNames){
		var dl = dojo.lang;
		var ao = {
			srcObj: dj_global,
			srcFunc: null,
			adviceObj: dj_global,
			adviceFunc: null,
			aroundObj: null,
			aroundFunc: null,
			adviceType: (args.length>2) ? args[0] : "after",
			precedence: "last",
			once: false,
			delay: null,
			rate: 0,
			adviceMsg: false
		};

		switch(args.length){
			case 0: return;
			case 1: return;
			case 2:
				ao.srcFunc = args[0];
				ao.adviceFunc = args[1];
				break;
			case 3:
				if((dl.isObject(args[0]))&&(dl.isString(args[1]))&&(dl.isString(args[2]))){
					ao.adviceType = "after";
					ao.srcObj = args[0];
					ao.srcFunc = args[1];
					ao.adviceFunc = args[2];
				}else if((dl.isString(args[1]))&&(dl.isString(args[2]))){
					ao.srcFunc = args[1];
					ao.adviceFunc = args[2];
				}else if((dl.isObject(args[0]))&&(dl.isString(args[1]))&&(dl.isFunction(args[2]))){
					ao.adviceType = "after";
					ao.srcObj = args[0];
					ao.srcFunc = args[1];
					var tmpName  = dl.nameAnonFunc(args[2], ao.adviceObj, searchForNames);
					ao.adviceFunc = tmpName;
				}else if((dl.isFunction(args[0]))&&(dl.isObject(args[1]))&&(dl.isString(args[2]))){
					ao.adviceType = "after";
					ao.srcObj = dj_global;
					var tmpName  = dl.nameAnonFunc(args[0], ao.srcObj, searchForNames);
					ao.srcFunc = tmpName;
					ao.adviceObj = args[1];
					ao.adviceFunc = args[2];
				}
				break;
			case 4:
				if((dl.isObject(args[0]))&&(dl.isObject(args[2]))){
					// we can assume that we've got an old-style "connect" from
					// the sigslot school of event attachment. We therefore
					// assume after-advice.
					ao.adviceType = "after";
					ao.srcObj = args[0];
					ao.srcFunc = args[1];
					ao.adviceObj = args[2];
					ao.adviceFunc = args[3];
				}else if((dl.isString(args[0]))&&(dl.isString(args[1]))&&(dl.isObject(args[2]))){
					ao.adviceType = args[0];
					ao.srcObj = dj_global;
					ao.srcFunc = args[1];
					ao.adviceObj = args[2];
					ao.adviceFunc = args[3];
				}else if((dl.isString(args[0]))&&(dl.isFunction(args[1]))&&(dl.isObject(args[2]))){
					ao.adviceType = args[0];
					ao.srcObj = dj_global;
					var tmpName  = dl.nameAnonFunc(args[1], dj_global, searchForNames);
					ao.srcFunc = tmpName;
					ao.adviceObj = args[2];
					ao.adviceFunc = args[3];
				}else if((dl.isString(args[0]))&&(dl.isObject(args[1]))&&(dl.isString(args[2]))&&(dl.isFunction(args[3]))){
					ao.srcObj = args[1];
					ao.srcFunc = args[2];
					var tmpName  = dl.nameAnonFunc(args[3], dj_global, searchForNames);
					ao.adviceObj = dj_global;
					ao.adviceFunc = tmpName;
				}else if(dl.isObject(args[1])){
					ao.srcObj = args[1];
					ao.srcFunc = args[2];
					ao.adviceObj = dj_global;
					ao.adviceFunc = args[3];
				}else if(dl.isObject(args[2])){
					ao.srcObj = dj_global;
					ao.srcFunc = args[1];
					ao.adviceObj = args[2];
					ao.adviceFunc = args[3];
				}else{
					ao.srcObj = ao.adviceObj = ao.aroundObj = dj_global;
					ao.srcFunc = args[1];
					ao.adviceFunc = args[2];
					ao.aroundFunc = args[3];
				}
				break;
			case 6:
				ao.srcObj = args[1];
				ao.srcFunc = args[2];
				ao.adviceObj = args[3]
				ao.adviceFunc = args[4];
				ao.aroundFunc = args[5];
				ao.aroundObj = dj_global;
				break;
			default:
				ao.srcObj = args[1];
				ao.srcFunc = args[2];
				ao.adviceObj = args[3]
				ao.adviceFunc = args[4];
				ao.aroundObj = args[5];
				ao.aroundFunc = args[6];
				ao.once = args[7];
				ao.delay = args[8];
				ao.rate = args[9];
				ao.adviceMsg = args[10];
				break;
		}

		if(dl.isFunction(ao.aroundFunc)){
			var tmpName  = dl.nameAnonFunc(ao.aroundFunc, ao.aroundObj, searchForNames);
			ao.aroundFunc = tmpName;
		}

		if(dl.isFunction(ao.srcFunc)){
			ao.srcFunc = dl.getNameInObj(ao.srcObj, ao.srcFunc);
		}

		if(dl.isFunction(ao.adviceFunc)){
			ao.adviceFunc = dl.getNameInObj(ao.adviceObj, ao.adviceFunc);
		}

		if((ao.aroundObj)&&(dl.isFunction(ao.aroundFunc))){
			ao.aroundFunc = dl.getNameInObj(ao.aroundObj, ao.aroundFunc);
		}

		if(!ao.srcObj){
			dojo.raise("bad srcObj for srcFunc: "+ao.srcFunc);
		}
		if(!ao.adviceObj){
			dojo.raise("bad adviceObj for adviceFunc: "+ao.adviceFunc);
		}
		return ao;
	}

	this.connect = function(){
		if(arguments.length == 1){
			var ao = arguments[0];
		}else{
			var ao = interpolateArgs(arguments, true);
		}

		if(dojo.lang.isArray(ao.srcObj) && ao.srcObj!=""){
			var tmpAO = {};
			for(var x in ao){
				tmpAO[x] = ao[x];
			}
			var mjps = [];
			dojo.lang.forEach(ao.srcObj, function(src){
				if((dojo.render.html.capable)&&(dojo.lang.isString(src))){
					src = dojo.byId(src);
					// dojo.debug(src);
				}
				tmpAO.srcObj = src;
				// dojo.debug(tmpAO.srcObj, tmpAO.srcFunc);
				// dojo.debug(tmpAO.adviceObj, tmpAO.adviceFunc);
				mjps.push(dojo.event.connect.call(dojo.event, tmpAO));
			});
			return mjps;
		}

		// FIXME: just doing a "getForMethod()" seems to be enough to put this into infinite recursion!!
		var mjp = dojo.event.MethodJoinPoint.getForMethod(ao.srcObj, ao.srcFunc);
		if(ao.adviceFunc){
			var mjp2 = dojo.event.MethodJoinPoint.getForMethod(ao.adviceObj, ao.adviceFunc);
		}

		mjp.kwAddAdvice(ao);

		return mjp;	// advanced users might want to fsck w/ the join point
					// manually
	}

	this.log = function(a1, a2){
		var kwArgs;
		if((arguments.length == 1)&&(typeof a1 == "object")){
			kwArgs = a1;
		}else{
			kwArgs = {
				srcObj: a1,
				srcFunc: a2
			};
		}
		kwArgs.adviceFunc = function(){
			var argsStr = [];
			for(var x=0; x<arguments.length; x++){
				argsStr.push(arguments[x]);
			}
			dojo.debug("("+kwArgs.srcObj+")."+kwArgs.srcFunc, ":", argsStr.join(", "));
		}
		this.kwConnect(kwArgs);
	}

	this.connectBefore = function(){
		var args = ["before"];
		for(var i = 0; i < arguments.length; i++) { args.push(arguments[i]); }
		return this.connect.apply(this, args);
	}

	this.connectAround = function(){
		var args = ["around"];
		for(var i = 0; i < arguments.length; i++) { args.push(arguments[i]); }
		return this.connect.apply(this, args);
	}

	this.connectOnce = function(){
		var ao = interpolateArgs(arguments, true);
		ao.once = true;
		return this.connect(ao);
	}

	this._kwConnectImpl = function(kwArgs, disconnect){
		var fn = (disconnect) ? "disconnect" : "connect";
		if(typeof kwArgs["srcFunc"] == "function"){
			kwArgs.srcObj = kwArgs["srcObj"]||dj_global;
			var tmpName  = dojo.lang.nameAnonFunc(kwArgs.srcFunc, kwArgs.srcObj, true);
			kwArgs.srcFunc = tmpName;
		}
		if(typeof kwArgs["adviceFunc"] == "function"){
			kwArgs.adviceObj = kwArgs["adviceObj"]||dj_global;
			var tmpName  = dojo.lang.nameAnonFunc(kwArgs.adviceFunc, kwArgs.adviceObj, true);
			kwArgs.adviceFunc = tmpName;
		}
		return dojo.event[fn](	(kwArgs["type"]||kwArgs["adviceType"]||"after"),
									kwArgs["srcObj"]||dj_global,
									kwArgs["srcFunc"],
									kwArgs["adviceObj"]||kwArgs["targetObj"]||dj_global,
									kwArgs["adviceFunc"]||kwArgs["targetFunc"],
									kwArgs["aroundObj"],
									kwArgs["aroundFunc"],
									kwArgs["once"],
									kwArgs["delay"],
									kwArgs["rate"],
									kwArgs["adviceMsg"]||false );
	}

	this.kwConnect = function(kwArgs){
		return this._kwConnectImpl(kwArgs, false);

	}

	this.disconnect = function(){
		var ao = interpolateArgs(arguments, true);
		if(!ao.adviceFunc){ return; } // nothing to disconnect
		var mjp = dojo.event.MethodJoinPoint.getForMethod(ao.srcObj, ao.srcFunc);
		return mjp.removeAdvice(ao.adviceObj, ao.adviceFunc, ao.adviceType, ao.once);
	}

	this.kwDisconnect = function(kwArgs){
		return this._kwConnectImpl(kwArgs, true);
	}
}

// exactly one of these is created whenever a method with a joint point is run,
// if there is at least one 'around' advice.
dojo.event.MethodInvocation = function(join_point, obj, args) {
	this.jp_ = join_point;
	this.object = obj;
	this.args = [];
	for(var x=0; x<args.length; x++){
		this.args[x] = args[x];
	}
	// the index of the 'around' that is currently being executed.
	this.around_index = -1;
}

dojo.event.MethodInvocation.prototype.proceed = function() {
	this.around_index++;
	if(this.around_index >= this.jp_.around.length){
		return this.jp_.object[this.jp_.methodname].apply(this.jp_.object, this.args);
		// return this.jp_.run_before_after(this.object, this.args);
	}else{
		var ti = this.jp_.around[this.around_index];
		var mobj = ti[0]||dj_global;
		var meth = ti[1];
		return mobj[meth].call(mobj, this);
	}
} 


dojo.event.MethodJoinPoint = function(obj, methname){
	this.object = obj||dj_global;
	this.methodname = methname;
	this.methodfunc = this.object[methname];
	this.before = [];
	this.after = [];
	this.around = [];
}

dojo.event.MethodJoinPoint.getForMethod = function(obj, methname) {
	// if(!(methname in obj)){
	if(!obj){ obj = dj_global; }
	if(!obj[methname]){
		// supply a do-nothing method implementation
		obj[methname] = function(){};
		if(!obj[methname]){
			// e.g. cannot add to inbuilt objects in IE6
			dojo.raise("Cannot set do-nothing method on that object "+methname);
		}
	}else if((!dojo.lang.isFunction(obj[methname]))&&(!dojo.lang.isAlien(obj[methname]))){
		return null; // FIXME: should we throw an exception here instead?
	}
	// we hide our joinpoint instance in obj[methname + '$joinpoint']
	var jpname = methname + "$joinpoint";
	var jpfuncname = methname + "$joinpoint$method";
	var joinpoint = obj[jpname];
	if(!joinpoint){
		var isNode = false;
		if(dojo.event["browser"]){
			if( (obj["attachEvent"])||
				(obj["nodeType"])||
				(obj["addEventListener"]) ){
				isNode = true;
				dojo.event.browser.addClobberNodeAttrs(obj, [jpname, jpfuncname, methname]);
			}
		}
		var origArity = obj[methname].length;
		obj[jpfuncname] = obj[methname];
		// joinpoint = obj[jpname] = new dojo.event.MethodJoinPoint(obj, methname);
		joinpoint = obj[jpname] = new dojo.event.MethodJoinPoint(obj, jpfuncname);
		obj[methname] = function(){ 
			var args = [];

			if((isNode)&&(!arguments.length)){
				var evt = null;
				try{
					if(obj.ownerDocument){
						evt = obj.ownerDocument.parentWindow.event;
					}else if(obj.documentElement){
						evt = obj.documentElement.ownerDocument.parentWindow.event;
					}else{
						evt = window.event;
					}
				}catch(e){
					evt = window.event;
				}

				if(evt){
					args.push(dojo.event.browser.fixEvent(evt, this));
				}
			}else{
				for(var x=0; x<arguments.length; x++){
					if((x==0)&&(isNode)&&(dojo.event.browser.isEvent(arguments[x]))){
						args.push(dojo.event.browser.fixEvent(arguments[x], this));
					}else{
						args.push(arguments[x]);
					}
				}
			}
			// return joinpoint.run.apply(joinpoint, arguments); 
			return joinpoint.run.apply(joinpoint, args); 
		}
		obj[methname].__preJoinArity = origArity;
	}
	return joinpoint;
}

dojo.lang.extend(dojo.event.MethodJoinPoint, {
	unintercept: function(){
		this.object[this.methodname] = this.methodfunc;
		this.before = [];
		this.after = [];
		this.around = [];
	},

	disconnect: dojo.lang.forward("unintercept"),

	run: function() {
		var obj = this.object||dj_global;
		var args = arguments;

		// optimization. We only compute once the array version of the arguments
		// pseudo-arr in order to prevent building it each time advice is unrolled.
		var aargs = [];
		for(var x=0; x<args.length; x++){
			aargs[x] = args[x];
		}

		var unrollAdvice  = function(marr){ 
			if(!marr){
				dojo.debug("Null argument to unrollAdvice()");
				return;
			}
		  
			var callObj = marr[0]||dj_global;
			var callFunc = marr[1];
			
			if(!callObj[callFunc]){
				dojo.raise("function \"" + callFunc + "\" does not exist on \"" + callObj + "\"");
			}
			
			var aroundObj = marr[2]||dj_global;
			var aroundFunc = marr[3];
			var msg = marr[6];
			var undef;

			var to = {
				args: [],
				jp_: this,
				object: obj,
				proceed: function(){
					return callObj[callFunc].apply(callObj, to.args);
				}
			};
			to.args = aargs;

			var delay = parseInt(marr[4]);
			var hasDelay = ((!isNaN(delay))&&(marr[4]!==null)&&(typeof marr[4] != "undefined"));
			if(marr[5]){
				var rate = parseInt(marr[5]);
				var cur = new Date();
				var timerSet = false;
				if((marr["last"])&&((cur-marr.last)<=rate)){
					if(dojo.event.canTimeout){
						if(marr["delayTimer"]){
							clearTimeout(marr.delayTimer);
						}
						var tod = parseInt(rate*2); // is rate*2 naive?
						var mcpy = dojo.lang.shallowCopy(marr);
						marr.delayTimer = setTimeout(function(){
							// FIXME: on IE at least, event objects from the
							// browser can go out of scope. How (or should?) we
							// deal with it?
							mcpy[5] = 0;
							unrollAdvice(mcpy);
						}, tod);
					}
					return;
				}else{
					marr.last = cur;
				}
			}

			// FIXME: need to enforce rates for a connection here!

			if(aroundFunc){
				// NOTE: around advice can't delay since we might otherwise depend
				// on execution order!
				aroundObj[aroundFunc].call(aroundObj, to);
			}else{
				// var tmjp = dojo.event.MethodJoinPoint.getForMethod(obj, methname);
				if((hasDelay)&&((dojo.render.html)||(dojo.render.svg))){  // FIXME: the render checks are grotty!
					dj_global["setTimeout"](function(){
						if(msg){
							callObj[callFunc].call(callObj, to); 
						}else{
							callObj[callFunc].apply(callObj, args); 
						}
					}, delay);
				}else{ // many environments can't support delay!
					if(msg){
						callObj[callFunc].call(callObj, to); 
					}else{
						callObj[callFunc].apply(callObj, args); 
					}
				}
			}
		}

		if(this.before.length>0){
			dojo.lang.forEach(this.before, unrollAdvice);
		}

		var result;
		if(this.around.length>0){
			var mi = new dojo.event.MethodInvocation(this, obj, args);
			result = mi.proceed();
		}else if(this.methodfunc){
			result = this.object[this.methodname].apply(this.object, args);
		}

		if(this.after.length>0){
			dojo.lang.forEach(this.after, unrollAdvice);
		}

		return (this.methodfunc) ? result : null;
	},

	getArr: function(kind){
		var arr = this.after;
		// FIXME: we should be able to do this through props or Array.in()
		if((typeof kind == "string")&&(kind.indexOf("before")!=-1)){
			arr = this.before;
		}else if(kind=="around"){
			arr = this.around;
		}
		return arr;
	},

	kwAddAdvice: function(args){
		this.addAdvice(	args["adviceObj"], args["adviceFunc"], 
						args["aroundObj"], args["aroundFunc"], 
						args["adviceType"], args["precedence"], 
						args["once"], args["delay"], args["rate"], 
						args["adviceMsg"]);
	},

	addAdvice: function(	thisAdviceObj, thisAdvice, 
							thisAroundObj, thisAround, 
							advice_kind, precedence, 
							once, delay, rate, asMessage){
		var arr = this.getArr(advice_kind);
		if(!arr){
			dojo.raise("bad this: " + this);
		}

		var ao = [thisAdviceObj, thisAdvice, thisAroundObj, thisAround, delay, rate, asMessage];
		
		if(once){
			if(this.hasAdvice(thisAdviceObj, thisAdvice, advice_kind, arr) >= 0){
				return;
			}
		}

		if(precedence == "first"){
			arr.unshift(ao);
		}else{
			arr.push(ao);
		}
	},

	hasAdvice: function(thisAdviceObj, thisAdvice, advice_kind, arr){
		if(!arr){ arr = this.getArr(advice_kind); }
		var ind = -1;
		for(var x=0; x<arr.length; x++){
			var aao = (typeof thisAdvice == "object") ? (new String(thisAdvice)).toString() : thisAdvice;
			var a1o = (typeof arr[x][1] == "object") ? (new String(arr[x][1])).toString() : arr[x][1];
			if((arr[x][0] == thisAdviceObj)&&(a1o == aao)){
				ind = x;
			}
		}
		return ind;
	},

	removeAdvice: function(thisAdviceObj, thisAdvice, advice_kind, once){
		var arr = this.getArr(advice_kind);
		var ind = this.hasAdvice(thisAdviceObj, thisAdvice, advice_kind, arr);
		if(ind == -1){
			return false;
		}
		while(ind != -1){
			arr.splice(ind, 1);
			if(once){ break; }
			ind = this.hasAdvice(thisAdviceObj, thisAdvice, advice_kind, arr);
		}
		return true;
	}
});
