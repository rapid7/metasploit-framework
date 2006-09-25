/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.io.ScriptSrcIO");
dojo.require("dojo.io.BrowserIO");
dojo.require("dojo.undo.browser");

//FIXME: should constantParams be JS object?
//FIXME: check dojo.io calls. Can we move the BrowserIO defined calls somewhere
//       else so that we don't depend on BrowserIO at all? The dependent calls
//       have to do with dealing with forms and making query params from JS object.
/**
 * See test_ScriptSrcIO.html for usage information.
 * Notes:
 * - The watchInFlight timer is set to 100 ms instead of 10ms (which is what BrowserIO.js uses).
 */
dojo.io.ScriptSrcTransport = new function(){
	this.preventCache = false; // if this is true, we'll always force GET requests to not cache
	this.maxUrlLength = 1000; //Used to calculate if script request should be multipart.
	this.inFlightTimer = null;

	this.DsrStatusCodes = {
		Continue: 100,
		Ok: 200,
		Error: 500
	};

	this.startWatchingInFlight = function(){
		if(!this.inFlightTimer){
			this.inFlightTimer = setInterval("dojo.io.ScriptSrcTransport.watchInFlight();", 100);
		}
	}

	this.watchInFlight = function(){
		var totalCount = 0;
		var doneCount = 0;
		for(var param in this._state){
			totalCount++;
			var currentState = this._state[param];
			if(currentState.isDone){
				doneCount++;
				delete this._state[param];
			}else{
				var listener = currentState.kwArgs;
				try{
					if(currentState.checkString && eval("typeof(" + currentState.checkString + ") != 'undefined'")){
						this._finish(currentState, "load");
						doneCount++;
						delete this._state[param];
					}else if(listener.timeoutSeconds && listener.timeout){
						if(currentState.startTime + (listener.timeoutSeconds * 1000) < (new Date()).getTime()){
							this._finish(currentState, "timeout");
							doneCount++;
							delete this._state[param];
						}
					}else if(!listener.timeoutSeconds){
						//Increment the done count if no timeout is specified, so
						//that we turn off the timer if all that is left in the state
						//list are things we can't clean up because they fail without
						//getting a callback.
						doneCount++;
					}
				}catch(e){
					this._finish(currentState, "error", {status: this.DsrStatusCodes.Error, response: e});
				}
			}
		}
	
		if(doneCount == totalCount){
			clearInterval(this.inFlightTimer);
			this.inFlightTimer = null;
		}
	}

	this.canHandle = function(kwArgs){
		return dojo.lang.inArray((kwArgs["mimetype"].toLowerCase()), ["text/javascript", "text/json"])
			&& (kwArgs["method"].toLowerCase() == "get")
			&& !(kwArgs["formNode"] && dojo.io.formHasFile(kwArgs["formNode"]))
			&& (!kwArgs["sync"] || kwArgs["sync"] == false)
			&& !kwArgs["file"]
			&& !kwArgs["multipart"];
	}

	/**
	 * Removes any script tags from the DOM that may have been added by ScriptSrcTransport.
	 * Be careful though, by removing them from the script, you may invalidate some
	 * script objects that were defined by the js file that was pulled in as the
	 * src of the script tag. Test carefully if you decide to call this method.
	 * 
	 * In MSIE 6 (and probably 5.x), if you removed the script element while 
	 * part of the script is still executing, the browser will crash.
	 */
	this.removeScripts = function(){
		var scripts = document.getElementsByTagName("script");
		for(var i = 0; scripts && i < scripts.length; i++){
			var scriptTag = scripts[i];
			if(scriptTag.className == "ScriptSrcTransport"){
				var parent = scriptTag.parentNode;
				parent.removeChild(scriptTag);
				i--; //Set the index back one since we removed an item.
			}
		}
	}

	this.bind = function(kwArgs){
		//START duplication from BrowserIO.js (some changes made)
		var url = kwArgs.url;
		var query = "";
		
		if(kwArgs["formNode"]){
			var ta = kwArgs.formNode.getAttribute("action");
			if((ta)&&(!kwArgs["url"])){ url = ta; }
			var tp = kwArgs.formNode.getAttribute("method");
			if((tp)&&(!kwArgs["method"])){ kwArgs.method = tp; }
			query += dojo.io.encodeForm(kwArgs.formNode, kwArgs.encoding, kwArgs["formFilter"]);
		}

		if(url.indexOf("#") > -1) {
			dojo.debug("Warning: dojo.io.bind: stripping hash values from url:", url);
			url = url.split("#")[0];
		}

		//Break off the domain/path of the URL.
		var urlParts = url.split("?");
		if(urlParts && urlParts.length == 2){
			url = urlParts[0];
			query += (query ? "&" : "") + urlParts[1];
		}

		if(kwArgs["backButton"] || kwArgs["back"] || kwArgs["changeUrl"]){
			dojo.undo.browser.addToHistory(kwArgs);
		}

		//Create an ID for the request.
		var id = kwArgs["apiId"] ? kwArgs["apiId"] : "id" + this._counter++;

		//Fill out any other content pieces.
		var content = kwArgs["content"];
		var jsonpName = kwArgs.jsonParamName;
		if(kwArgs.sendTransport || jsonpName) {
			if (!content){
				content = {};
			}
			if(kwArgs.sendTransport){
				content["dojo.transport"] = "scriptsrc";
			}

			if(jsonpName){
				content[jsonpName] = "dojo.io.ScriptSrcTransport._state." + id + ".jsonpCall";
			}
		}

		if(kwArgs.postContent){
			query = kwArgs.postContent;
		}else if(content){
			query += ((query) ? "&" : "") + dojo.io.argsFromMap(content, kwArgs.encoding, jsonpName);
		}
		//END duplication from BrowserIO.js

		//START DSR

		//If an apiId is specified, then we want to make sure useRequestId is true.
		if(kwArgs["apiId"]){
			kwArgs["useRequestId"] = true;
		}

		//Set up the state for this request.
		var state = {
			"id": id,
			"idParam": "_dsrid=" + id,
			"url": url,
			"query": query,
			"kwArgs": kwArgs,
			"startTime": (new Date()).getTime()
		};

		if(!url){
			//Error. An URL is needed.
			this._finish(state, "error", {status: this.DsrStatusCodes.Error, statusText: "url.none"});
			return;
		}

		//If this is a jsonp request, intercept the jsonp callback
		if(content && content[jsonpName]){
			state.jsonp = content[jsonpName];
			state.jsonpCall = function(data){
				if(data["Error"]||data["error"]){
					dojo.debug(dojo.json.serialize(data));
					dojo.io.ScriptSrcTransport._finish(this, "error", data);
				}else{
					dojo.io.ScriptSrcTransport._finish(this, "load", data);
				}
			};
		}

		//Only store the request state on the state tracking object if a callback
		//is expected or if polling on a checkString will be done.
		if(kwArgs["useRequestId"] || kwArgs["checkString"] || state["jsonp"]){
			this._state[id] = state;
		}

		//A checkstring is a string that if evaled will not be undefined once the
		//script src loads. Used as an alternative to depending on a callback from
		//the script file. If this is set, then multipart is not assumed to be used,
		//since multipart requires a specific callback. With checkString we will be doing
		//polling.
		if(kwArgs["checkString"]){
			state.checkString = kwArgs["checkString"];
		}

		//Constant params are parameters that should always be sent with each
		//part of a multipart URL.
		state.constantParams = (kwArgs["constantParams"] == null ? "" : kwArgs["constantParams"]);
	
		if(kwArgs["preventCache"] ||
			(this.preventCache == true && kwArgs["preventCache"] != false)){
			state.nocacheParam = "dojo.preventCache=" + new Date().valueOf();
		}else{
			state.nocacheParam = "";
		}

		//Get total length URL, if we were to do it as one URL.
		//Add some padding, extra & separators.
		var urlLength = state.url.length + state.query.length + state.constantParams.length 
				+ state.nocacheParam.length + this._extraPaddingLength;

		if(kwArgs["useRequestId"]){
			urlLength += state.idParam.length;
		}
		
		if(!kwArgs["checkString"] && kwArgs["useRequestId"] 
			&& !state["jsonp"] && !kwArgs["forceSingleRequest"]
			&& urlLength > this.maxUrlLength){
			if(url > this.maxUrlLength){
				//Error. The URL domain and path are too long. We can't
				//segment that, so return an error.
				this._finish(state, "error", {status: this.DsrStatusCodes.Error, statusText: "url.tooBig"});
				return;
			}else{
				//Start the multiple requests.
				this._multiAttach(state, 1);
			}
		}else{
			//Send one URL.
			var queryParams = [state.constantParams, state.nocacheParam, state.query];
			if(kwArgs["useRequestId"] && !state["jsonp"]){
				queryParams.unshift(state.idParam);
			}
			var finalUrl = this._buildUrl(state.url, queryParams);

			//Track the final URL in case we need to use that instead of api ID when receiving
			//the load callback.
			state.finalUrl = finalUrl;
			
			this._attach(state.id, finalUrl);
		}
		//END DSR

		this.startWatchingInFlight();
	}
	
	//Private properties/methods
	this._counter = 1;
	this._state = {};
	this._extraPaddingLength = 16;

	//Is there a dojo function for this already?
	this._buildUrl = function(url, nameValueArray){
		var finalUrl = url;
		var joiner = "?";
		for(var i = 0; i < nameValueArray.length; i++){
			if(nameValueArray[i]){
				finalUrl += joiner + nameValueArray[i];
				joiner = "&";
			}
		}

		return finalUrl;
	}

	this._attach = function(id, url){
		//Attach the script to the DOM.
		var element = document.createElement("script");
		element.type = "text/javascript";
		element.src = url;
		element.id = id;
		element.className = "ScriptSrcTransport";
		document.getElementsByTagName("head")[0].appendChild(element);
	}

	this._multiAttach = function(state, part){
		//Check to make sure we still have a query to send up. This is mostly
		//a protection from a goof on the server side when it sends a part OK
		//response instead of a final response.
		if(state.query == null){
			this._finish(state, "error", {status: this.DsrStatusCodes.Error, statusText: "query.null"});
			return;
		}

		if(!state.constantParams){
			state.constantParams = "";
		}

		//How much of the query can we take?
		//Add a padding constant to account for _part and a couple extra amperstands.
		//Also add space for id since we'll need it now.
		var queryMax = this.maxUrlLength - state.idParam.length
					 - state.constantParams.length - state.url.length
					 - state.nocacheParam.length - this._extraPaddingLength;
		
		//Figure out if this is the last part.
		var isDone = state.query.length < queryMax;
	
		//Break up the query string if necessary.
		var currentQuery;
		if(isDone){
			currentQuery = state.query;
			state.query = null;
		}else{
			//Find the & or = nearest the max url length.
			var ampEnd = state.query.lastIndexOf("&", queryMax - 1);
			var eqEnd = state.query.lastIndexOf("=", queryMax - 1);

			//See if & is closer, or if = is right at the edge,
			//which means we should put it on the next URL.
			if(ampEnd > eqEnd || eqEnd == queryMax - 1){
				//& is nearer the end. So just chop off from there.
				currentQuery = state.query.substring(0, ampEnd);
				state.query = state.query.substring(ampEnd + 1, state.query.length) //strip off amperstand with the + 1.
			}else{
				//= is nearer the end. Take the max amount possible. 
				currentQuery = state.query.substring(0, queryMax);
			 
				//Find the last query name in the currentQuery so we can prepend it to
				//ampEnd. Could be -1 (not there), so account for that.
				var queryName = currentQuery.substring((ampEnd == -1 ? 0 : ampEnd + 1), eqEnd);
				state.query = queryName + "=" + state.query.substring(queryMax, state.query.length);
			}
		}
		
		//Now send a part of the script
		var queryParams = [currentQuery, state.idParam, state.constantParams, state.nocacheParam];
		if(!isDone){
			queryParams.push("_part=" + part);
		}

		var url = this._buildUrl(state.url, queryParams);

		this._attach(state.id + "_" + part, url);
	}

	this._finish = function(state, callback, event){
		if(callback != "partOk" && !state.kwArgs[callback] && !state.kwArgs["handle"]){
			//Ignore "partOk" because that is an internal callback.
			if(callback == "error"){
				state.isDone = true;
				throw event;
			}
		}else{
			switch(callback){
				case "load":
					var response = event ? event.response : null;
					if(!response){
						response = event;
					}
					state.kwArgs[(typeof state.kwArgs.load == "function") ? "load" : "handle"]("load", response, event, state.kwArgs);
					state.isDone = true;
					break;
				case "partOk":
					var part = parseInt(event.response.part, 10) + 1;
					//Update the constant params, if any.
					if(event.response.constantParams){
						state.constantParams = event.response.constantParams;
					}
					this._multiAttach(state, part);
					state.isDone = false;
					break;
				case "error":
					state.kwArgs[(typeof state.kwArgs.error == "function") ? "error" : "handle"]("error", event.response, event, state.kwArgs);
					state.isDone = true;
					break;
				default:
					state.kwArgs[(typeof state.kwArgs[callback] == "function") ? callback : "handle"](callback, event, event, state.kwArgs);
					state.isDone = true;
			}
		}
	}

	dojo.io.transports.addTransport("ScriptSrcTransport");
}

//Define callback handler.
window.onscriptload = function(event){
	var state = null;
	var transport = dojo.io.ScriptSrcTransport;
	
	//Find the matching state object for event ID.
	if(transport._state[event.id]){
		state = transport._state[event.id];
	}else{
		//The ID did not match directly to an entry in the state list.
		//Try searching the state objects for a matching original URL.
		var tempState;
		for(var param in transport._state){
			tempState = transport._state[param];
			if(tempState.finalUrl && tempState.finalUrl == event.id){
				state = tempState;
				break;
			}
		}

		//If no matching original URL is found, then use the URL that was actually used
		//in the SCRIPT SRC attribute.
		if(state == null){
			var scripts = document.getElementsByTagName("script");
			for(var i = 0; scripts && i < scripts.length; i++){
				var scriptTag = scripts[i];
				if(scriptTag.getAttribute("class") == "ScriptSrcTransport"
					&& scriptTag.src == event.id){
					state = transport._state[scriptTag.id];
					break;
				}
			}
		}
		
		//If state is still null, then throw an error.
		if(state == null){
			throw "No matching state for onscriptload event.id: " + event.id;
		}
	}

	var callbackName = "error";
	switch(event.status){
		case dojo.io.ScriptSrcTransport.DsrStatusCodes.Continue:
			//A part of a multipart request.
			callbackName = "partOk";
			break;
		case dojo.io.ScriptSrcTransport.DsrStatusCodes.Ok:
			//Successful reponse.
			callbackName = "load";
			break;
	}

	transport._finish(state, callbackName, event);
};
