/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.io.IO");
dojo.require("dojo.string");
dojo.require("dojo.lang.extras");

/******************************************************************************
 *	Notes about dojo.io design:
 *	
 *	The dojo.io.* package has the unenviable task of making a lot of different
 *	types of I/O feel natural, despite a universal lack of good (or even
 *	reasonable!) I/O capability in the host environment. So lets pin this down
 *	a little bit further.
 *
 *	Rhino:
 *		perhaps the best situation anywhere. Access to Java classes allows you
 *		to do anything one might want in terms of I/O, both synchronously and
 *		async. Can open TCP sockets and perform low-latency client/server
 *		interactions. HTTP transport is available through Java HTTP client and
 *		server classes. Wish it were always this easy.
 *
 *	xpcshell:
 *		XPCOM for I/O. A cluster-fuck to be sure.
 *
 *	spidermonkey:
 *		S.O.L.
 *
 *	Browsers:
 *		Browsers generally do not provide any useable filesystem access. We are
 *		therefore limited to HTTP for moving information to and from Dojo
 *		instances living in a browser.
 *
 *		XMLHTTP:
 *			Sync or async, allows reading of arbitrary text files (including
 *			JS, which can then be eval()'d), writing requires server
 *			cooperation and is limited to HTTP mechanisms (POST and GET).
 *
 *		<iframe> hacks:
 *			iframe document hacks allow browsers to communicate asynchronously
 *			with a server via HTTP POST and GET operations. With significant
 *			effort and server cooperation, low-latency data transit between
 *			client and server can be acheived via iframe mechanisms (repubsub).
 *
 *		SVG:
 *			Adobe's SVG viewer implements helpful primitives for XML-based
 *			requests, but receipt of arbitrary text data seems unlikely w/o
 *			<![CDATA[]]> sections.
 *
 *
 *	A discussion between Dylan, Mark, Tom, and Alex helped to lay down a lot
 *	the IO API interface. A transcript of it can be found at:
 *		http://dojotoolkit.org/viewcvs/viewcvs.py/documents/irc/irc_io_api_log.txt?rev=307&view=auto
 *	
 *	Also referenced in the design of the API was the DOM 3 L&S spec:
 *		http://www.w3.org/TR/2004/REC-DOM-Level-3-LS-20040407/load-save.html
 ******************************************************************************/

// a map of the available transport options. Transports should add themselves
// by calling add(name)
dojo.io.transports = [];
dojo.io.hdlrFuncNames = [ "load", "error", "timeout" ]; // we're omitting a progress() event for now

dojo.io.Request = function(url, mimetype, transport, changeUrl){
	if((arguments.length == 1)&&(arguments[0].constructor == Object)){
		this.fromKwArgs(arguments[0]);
	}else{
		this.url = url;
		if(mimetype){ this.mimetype = mimetype; }
		if(transport){ this.transport = transport; }
		if(arguments.length >= 4){ this.changeUrl = changeUrl; }
	}
}

dojo.lang.extend(dojo.io.Request, {

	/** The URL to hit */
	url: "",
	
	/** The mime type used to interrpret the response body */
	mimetype: "text/plain",
	
	/** The HTTP method to use */
	method: "GET",
	
	/** An Object containing key-value pairs to be included with the request */
	content: undefined, // Object
	
	/** The transport medium to use */
	transport: undefined, // String
	
	/** If defined the URL of the page is physically changed */
	changeUrl: undefined, // String
	
	/** A form node to use in the request */
	formNode: undefined, // HTMLFormElement
	
	/** Whether the request should be made synchronously */
	sync: false,
	
	bindSuccess: false,

	/** Cache/look for the request in the cache before attempting to request?
	 *  NOTE: this isn't a browser cache, this is internal and would only cache in-page
	 */
	useCache: false,

	/** Prevent the browser from caching this by adding a query string argument to the URL */
	preventCache: false,
	
	// events stuff
	load: function(type, data, evt){ },
	error: function(type, error){ },
	timeout: function(type){ },
	handle: function(){ },

	//FIXME: change BrowserIO.js to use timeouts? IframeIO?
	// The number of seconds to wait until firing a timeout callback.
	// If it is zero, that means, don't do a timeout check.
	timeoutSeconds: 0,
	
	// the abort method needs to be filled in by the transport that accepts the
	// bind() request
	abort: function(){ },
	
	// backButton: function(){ },
	// forwardButton: function(){ },

	fromKwArgs: function(kwArgs){
		// normalize args
		if(kwArgs["url"]){ kwArgs.url = kwArgs.url.toString(); }
		if(kwArgs["formNode"]) { kwArgs.formNode = dojo.byId(kwArgs.formNode); }
		if(!kwArgs["method"] && kwArgs["formNode"] && kwArgs["formNode"].method) {
			kwArgs.method = kwArgs["formNode"].method;
		}
		
		// backwards compatibility
		if(!kwArgs["handle"] && kwArgs["handler"]){ kwArgs.handle = kwArgs.handler; }
		if(!kwArgs["load"] && kwArgs["loaded"]){ kwArgs.load = kwArgs.loaded; }
		if(!kwArgs["changeUrl"] && kwArgs["changeURL"]) { kwArgs.changeUrl = kwArgs.changeURL; }

		// encoding fun!
		kwArgs.encoding = dojo.lang.firstValued(kwArgs["encoding"], djConfig["bindEncoding"], "");

		kwArgs.sendTransport = dojo.lang.firstValued(kwArgs["sendTransport"], djConfig["ioSendTransport"], false);

		var isFunction = dojo.lang.isFunction;
		for(var x=0; x<dojo.io.hdlrFuncNames.length; x++){
			var fn = dojo.io.hdlrFuncNames[x];
			if(isFunction(kwArgs[fn])){ continue; }
			if(isFunction(kwArgs["handle"])){
				kwArgs[fn] = kwArgs.handle;
			}
			// handler is aliased above, shouldn't need this check
			/* else if(dojo.lang.isObject(kwArgs.handler)){
				if(isFunction(kwArgs.handler[fn])){
					kwArgs[fn] = kwArgs.handler[fn]||kwArgs.handler["handle"]||function(){};
				}
			}*/
		}
		dojo.lang.mixin(this, kwArgs);
	}

});

dojo.io.Error = function(msg, type, num){
	this.message = msg;
	this.type =  type || "unknown"; // must be one of "io", "parse", "unknown"
	this.number = num || 0; // per-substrate error number, not normalized
}

dojo.io.transports.addTransport = function(name){
	this.push(name);
	// FIXME: do we need to handle things that aren't direct children of the
	// dojo.io namespace? (say, dojo.io.foo.fooTransport?)
	this[name] = dojo.io[name];
}

// binding interface, the various implementations register their capabilities
// and the bind() method dispatches
dojo.io.bind = function(request){
	// if the request asks for a particular implementation, use it
	if(!(request instanceof dojo.io.Request)){
		try{
			request = new dojo.io.Request(request);
		}catch(e){ dojo.debug(e); }
	}
	var tsName = "";
	if(request["transport"]){
		tsName = request["transport"];
		// FIXME: it would be good to call the error handler, although we'd
		// need to use setTimeout or similar to accomplish this and we can't
		// garuntee that this facility is available.
		if(!this[tsName]){ return request; }
	}else{
		// otherwise we do our best to auto-detect what available transports
		// will handle 
		for(var x=0; x<dojo.io.transports.length; x++){
			var tmp = dojo.io.transports[x];
			if((this[tmp])&&(this[tmp].canHandle(request))){
				tsName = tmp;
			}
		}
		if(tsName == ""){ return request; }
	}
	this[tsName].bind(request);
	request.bindSuccess = true;
	return request;
}

dojo.io.queueBind = function(request){
	if(!(request instanceof dojo.io.Request)){
		try{
			request = new dojo.io.Request(request);
		}catch(e){ dojo.debug(e); }
	}

	// make sure we get called if/when we get a response
	var oldLoad = request.load;
	request.load = function(){
		dojo.io._queueBindInFlight = false;
		var ret = oldLoad.apply(this, arguments);
		dojo.io._dispatchNextQueueBind();
		return ret;
	}

	var oldErr = request.error;
	request.error = function(){
		dojo.io._queueBindInFlight = false;
		var ret = oldErr.apply(this, arguments);
		dojo.io._dispatchNextQueueBind();
		return ret;
	}

	dojo.io._bindQueue.push(request);
	dojo.io._dispatchNextQueueBind();
	return request;
}

dojo.io._dispatchNextQueueBind = function(){
	if(!dojo.io._queueBindInFlight){
		dojo.io._queueBindInFlight = true;
		if(dojo.io._bindQueue.length > 0){
			dojo.io.bind(dojo.io._bindQueue.shift());
		}else{
			dojo.io._queueBindInFlight = false;
		}
	}
}
dojo.io._bindQueue = [];
dojo.io._queueBindInFlight = false;

dojo.io.argsFromMap = function(map, encoding, last){
	var enc = /utf/i.test(encoding||"") ? encodeURIComponent : dojo.string.encodeAscii;
	var mapped = [];
	var control = new Object();
	for(var name in map){
		var domap = function(elt){
			var val = enc(name)+"="+enc(elt);
			mapped[(last == name) ? "push" : "unshift"](val);
		}
		if(!control[name]){
			var value = map[name];
			// FIXME: should be isArrayLike?
			if (dojo.lang.isArray(value)){
				dojo.lang.forEach(value, domap);
			}else{
				domap(value);
			}
		}
	}
	return mapped.join("&");
}

dojo.io.setIFrameSrc = function(iframe, src, replace){
	try{
		var r = dojo.render.html;
		// dojo.debug(iframe);
		if(!replace){
			if(r.safari){
				iframe.location = src;
			}else{
				frames[iframe.name].location = src;
			}
		}else{
			// Fun with DOM 0 incompatibilities!
			var idoc;
			if(r.ie){
				idoc = iframe.contentWindow.document;
			}else if(r.safari){
				idoc = iframe.document;
			}else{ //  if(r.moz){
				idoc = iframe.contentWindow;
			}

			//For Safari (at least 2.0.3) and Opera, if the iframe
			//has just been created but it doesn't have content
			//yet, then iframe.document may be null. In that case,
			//use iframe.location and return.
			if(!idoc){
				iframe.location = src;
				return;
			}else{
				idoc.location.replace(src);
			}
		}
	}catch(e){ 
		dojo.debug(e); 
		dojo.debug("setIFrameSrc: "+e); 
	}
}

/*
dojo.io.sampleTranport = new function(){
	this.canHandle = function(kwArgs){
		// canHandle just tells dojo.io.bind() if this is a good transport to
		// use for the particular type of request.
		if(	
			(
				(kwArgs["mimetype"] == "text/plain") ||
				(kwArgs["mimetype"] == "text/html") ||
				(kwArgs["mimetype"] == "text/javascript")
			)&&(
				(kwArgs["method"] == "get") ||
				( (kwArgs["method"] == "post") && (!kwArgs["formNode"]) )
			)
		){
			return true;
		}

		return false;
	}

	this.bind = function(kwArgs){
		var hdlrObj = {};

		// set up a handler object
		for(var x=0; x<dojo.io.hdlrFuncNames.length; x++){
			var fn = dojo.io.hdlrFuncNames[x];
			if(typeof kwArgs.handler == "object"){
				if(typeof kwArgs.handler[fn] == "function"){
					hdlrObj[fn] = kwArgs.handler[fn]||kwArgs.handler["handle"];
				}
			}else if(typeof kwArgs[fn] == "function"){
				hdlrObj[fn] = kwArgs[fn];
			}else{
				hdlrObj[fn] = kwArgs["handle"]||function(){};
			}
		}

		// build a handler function that calls back to the handler obj
		var hdlrFunc = function(evt){
			if(evt.type == "onload"){
				hdlrObj.load("load", evt.data, evt);
			}else if(evt.type == "onerr"){
				var errObj = new dojo.io.Error("sampleTransport Error: "+evt.msg);
				hdlrObj.error("error", errObj);
			}
		}

		// the sample transport would attach the hdlrFunc() when sending the
		// request down the pipe at this point
		var tgtURL = kwArgs.url+"?"+dojo.io.argsFromMap(kwArgs.content);
		// sampleTransport.sendRequest(tgtURL, hdlrFunc);
	}

	dojo.io.transports.addTransport("sampleTranport");
}
*/
