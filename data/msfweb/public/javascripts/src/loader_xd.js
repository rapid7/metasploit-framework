/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

//Cross-domain package loader.

//FIXME: How will xd loading work with debugAtAllCosts? Any bad interactions?
//FIXME: widgets won't work fully (HTML/CSS) and also because of the requireIf() thing.

dojo.hostenv.resetXd = function(){
	//This flag indicates where or not we have crossed into xdomain territory. Once any package says
	//it is cross domain, then the rest of the packages have to be treated as xdomain because we need
	//to evaluate packages in order. If there is a xdomain package followed by a xhr package, we can't load
	//the xhr package until the one before it finishes loading. The text of the xhr package will be converted
	//to match the format for a xd package and put in the xd load queue.
	//You can force all packages to be treated as xd by setting the djConfig.forceXDomain.
	this.isXDomain = djConfig.forceXDomain || false;

	this.xdTimer = 0;
	this.xdInFlight = {};
	this.xdOrderedReqs = [];
	this.xdDepMap = {};
	this.xdContents = [];
}

//Call reset immediately to set the state.
dojo.hostenv.resetXd();

dojo.hostenv.createXdPackage = function(contents){
	//Find dependencies.
	var deps = [];
    var depRegExp = /dojo.(require|requireIf|requireAll|provide|requireAfterIf|requireAfter|kwCompoundRequire|conditionalRequire|hostenv\.conditionalLoadModule|.hostenv\.loadModule|hostenv\.moduleLoaded)\(([\w\W]*?)\)/mg;
    var match;
	while((match = depRegExp.exec(contents)) != null){
		deps.push("\"" + match[1] + "\", " + match[2]);
	}

	//Create package object and the call to packageLoaded.
	var output = [];
	output.push("dojo.hostenv.packageLoaded({\n");

	//Add dependencies
	if(deps.length > 0){
		output.push("depends: [");
		for(var i = 0; i < deps.length; i++){
			if(i > 0){
				output.push(",\n");
			}
			output.push("[" + deps[i] + "]");
		}
		output.push("],");
	}

	//Add the contents of the file inside a function.
	//Pass in dojo as an argument to the function to help with
	//allowing multiple versions of dojo in a page.
	output.push("\ndefinePackage: function(dojo){");
	output.push(contents);
	output.push("\n}});");
	
	return output.join("");
}

dojo.hostenv.loadPath = function(relpath, module /*optional*/, cb /*optional*/){
	//Only do getBaseScriptUri if path does not start with a URL with a protocol.
	//If there is a colon before the first / then, we have a URL with a protocol.
	var colonIndex = relpath.indexOf(":");
	var slashIndex = relpath.indexOf("/");
	var uri;
	var currentIsXDomain = false;
	if(colonIndex > 0 && colonIndex < slashIndex){
		uri = relpath;
		this.isXDomain = currentIsXDomain = true;
	}else{
		uri = this.getBaseScriptUri() + relpath;

		//Is ithe base script URI-based URL a cross domain URL?
		colonIndex = uri.indexOf(":");
		slashIndex = uri.indexOf("/");
		if(colonIndex > 0 && colonIndex < slashIndex && (!location.host || uri.indexOf("http://" + location.host) != 0)){
			this.isXDomain = currentIsXDomain = true;
		}
	}

	if(djConfig.cacheBust && dojo.render.html.capable) { uri += "?" + String(djConfig.cacheBust).replace(/\W+/g,""); }
	try{
		return ((!module || this.isXDomain) ? this.loadUri(uri, cb, currentIsXDomain, module) : this.loadUriAndCheck(uri, module, cb));
	}catch(e){
		dojo.debug(e);
		return false;
	}
}

//Overriding loadUri for now. Wanted to override getText(), but it is used by
//the widget code in too many, synchronous ways right now. This means the xd stuff
//is not suitable for widgets yet.
dojo.hostenv.loadUri = function(uri, cb, currentIsXDomain, module){
	if(this.loadedUris[uri]){
		return 1;
	}

	//Add the module (package) to the list of modules.
	if(this.isXDomain){
		//Curious: is this array going to get whacked with multiple access since scripts
		//load asynchronously and may be accessing the array at the same time?
		//JS is single-threaded supposedly, so it should be ok. And we don't need
		//a precise ordering.
		this.xdOrderedReqs.push(module);

		//Add to waiting packages.
		//If this is a __package__.js file, then this must be
		//a package.* request (since xdomain can only work with the first
		//path in a package search list. However, .* module names are not
		//passed to this function, so do an adjustment here.
		if(uri.indexOf("__package__") != -1){
			module += ".*";
		}

		this.xdInFlight[module] = true;

		//Increment inFlightCount
		//This will stop the modulesLoaded from firing all the way.
		this.inFlightCount++;
				
		//Start timer
		if(!this.xdTimer){
			this.xdTimer = setInterval("dojo.hostenv.watchInFlightXDomain();", 100);
		}
		this.xdStartTime = (new Date()).getTime();
	}

	if (currentIsXDomain){
		//Fix name to be a .xd.fileextension name.
		var lastIndex = uri.lastIndexOf('.');
		if(lastIndex <= 0){
			lastIndex = uri.length - 1;
		}

		var xdUri = uri.substring(0, lastIndex) + ".xd";
		if(lastIndex != uri.length - 1){
			xdUri += uri.substring(lastIndex, uri.length);
		}

		//Add to script src
		var element = document.createElement("script");
		element.type = "text/javascript";
		element.src = xdUri;
		if(!this.headElement){
			this.headElement = document.getElementsByTagName("head")[0];
		}
		this.headElement.appendChild(element);
	}else{
		var contents = this.getText(uri, null, true);
		if(contents == null){ return 0; }
		
		if(this.isXDomain){
			var pkg = this.createXdPackage(contents);
			dj_eval(pkg);
		}else{
			if(cb){ contents = '('+contents+')'; }
			var value = dj_eval(contents);
			if(cb){
				cb(value);
			}
		}
	}

	//These steps are done in the non-xd loader version of this function.
	//Maintain these steps to fit in with the existing system.
	this.loadedUris[uri] = true;
	return 1;
}

dojo.hostenv.packageLoaded = function(pkg){
	var deps = pkg.depends;
	var requireList = null;
	var requireAfterList = null;
	var provideList = [];
	if(deps && deps.length > 0){
		var dep = null;
		var insertHint = 0;
		var attachedPackage = false;
		for(var i = 0; i < deps.length; i++){
			dep = deps[i];

			//Look for specific dependency indicators.
			if (dep[0] == "provide" || dep[0] == "hostenv.moduleLoaded"){
				provideList.push(dep[1]);
			}else{
				if(!requireList){
					requireList = [];
				}
				if(!requireAfterList){
					requireAfterList = [];
				}

				var unpackedDeps = this.unpackXdDependency(dep);
				if(unpackedDeps.requires){
					requireList = requireList.concat(unpackedDeps.requires);
				}
				if(unpackedDeps.requiresAfter){
					requireAfterList = requireAfterList.concat(unpackedDeps.requiresAfter);
				}
			}

			//Call the dependency indicator to allow for the normal dojo setup.
			//Only allow for one dot reference, for the hostenv.* type calls.
			var depType = dep[0];
			var objPath = depType.split(".");
			if(objPath.length == 2){
				dojo[objPath[0]][objPath[1]].apply(dojo[objPath[0]], dep.slice(1));
			}else{
				dojo[depType].apply(dojo, dep.slice(1));
			}
		}

		//Save off the package contents for definition later.
		var contentIndex = this.xdContents.push({content: pkg.definePackage, isDefined: false}) - 1;

		//Add provide/requires to dependency map.
		for(var i = 0; i < provideList.length; i++){
			this.xdDepMap[provideList[i]] = { requires: requireList, requiresAfter: requireAfterList, contentIndex: contentIndex };
		}

		//Now update the inflight status for any provided packages in this loaded package.
		//Do this at the very end (in a *separate* for loop) to avoid shutting down the 
		//inflight timer check too soon.
		for(var i = 0; i < provideList.length; i++){
			this.xdInFlight[provideList[i]] = false;
		}
	}
}

//This is a bit brittle: it has to know about the dojo methods that deal with dependencies
//It would be ideal to intercept the actual methods and do something fancy at that point,
//but I have concern about knowing which provide to match to the dependency in that case,
//since scripts can load whenever they want, and trigger new calls to dojo.hostenv.packageLoaded().
dojo.hostenv.unpackXdDependency = function(dep){
	//Extract the dependency(ies).
	var newDeps = null;
	var newAfterDeps = null;
	switch(dep[0]){
		case "requireIf":
		case "requireAfterIf":
		case "conditionalRequire":
			//First arg (dep[1]) is the test. Depedency is dep[2].
			if((dep[1] === true)||(dep[1]=="common")||(dep[1] && dojo.render[dep[1]].capable)){
				newDeps = [{name: dep[2], content: null}];
			}
			break;
		case "requireAll":
			//the arguments are an array, each element a call to require.
			//Get rid of first item, which is "requireAll".
			dep.shift();
			newDeps = dep;
			dojo.hostenv.flattenRequireArray(newDeps);
			break;
		case "kwCompoundRequire":
		case "hostenv.conditionalLoadModule":
			var modMap = dep[1];
			var common = modMap["common"]||[];
			var newDeps = (modMap[dojo.hostenv.name_]) ? common.concat(modMap[dojo.hostenv.name_]||[]) : common.concat(modMap["default"]||[]);	
			dojo.hostenv.flattenRequireArray(newDeps);
			break;
		case "require":
		case "requireAfter":
		case "hostenv.loadModule":
			//Just worry about dep[1]
			newDeps = [{name: dep[1], content: null}];
			break;
	}

	//The requireAfterIf or requireAfter needs to be evaluated after the current package is evaluated.
	if(dep[0] == "requireAfterIf"){
		newAfterDeps = newDeps;
		newDeps = null;
	}
	return {requires: newDeps, requiresAfter: newAfterDeps};
}

//Walks the requires and evaluates package contents in
//the right order.
dojo.hostenv.xdWalkReqs = function(){
	var reqChain = null;
	var req;
	for(var i = 0; i < this.xdOrderedReqs.length; i++){
		req = this.xdOrderedReqs[i];
		if(this.xdDepMap[req]){
			reqChain = [req];
			reqChain[req] = true; //Allow for fast lookup of the req in the array
			this.xdEvalReqs(reqChain);
		}
	}
}

//Trace down any requires.
dojo.hostenv.xdTraceReqs = function(reqs, reqChain){
	if(reqs && reqs.length > 0){
		var nextReq;
		for(var i = 0; i < reqs.length; i++){
			nextReq = reqs[i].name;
			if(nextReq && !reqChain[nextReq]){
				//New req depedency. Follow it down.
				reqChain.push(nextReq);
				reqChain[nextReq] = true;
				this.xdEvalReqs(reqChain);
			}
		}
	}
}

//Do a depth first, breadth second search and eval or reqs.
dojo.hostenv.xdEvalReqs = function(reqChain){
	if(reqChain.length > 0){
		var req = reqChain[reqChain.length - 1];
		var pkg = this.xdDepMap[req];
		if(pkg){
			//Trace down any requires for this package.
			this.xdTraceReqs(pkg.requires, reqChain);

			//Evaluate the package.
			var contents = this.xdContents[pkg.contentIndex];
			if(!contents.isDefined){
				//Evaluate the package to bring it into being.
				//Pass dojo in so that later, to support multiple versions of dojo
				//in a page, we can pass which version of dojo to use.
				contents.content(dojo);
				contents.isDefined = true;
			}
			this.xdDepMap[req] = null;

			//Trace down any requireAfters for this package..
			this.xdTraceReqs(pkg.requiresAfter, reqChain);
		}

		//Done with that require. Remove it and go to the next one.
		reqChain.pop();
		this.xdEvalReqs(reqChain);
	}
}

dojo.hostenv.clearXdInterval = function(){
	clearInterval(this.xdTimer);
	this.xdTimer = 0;
}

dojo.hostenv.watchInFlightXDomain = function(){
	//Make sure we haven't waited timed out.
	var waitInterval = (djConfig.xdWaitSeconds || 30) * 1000;

	if(this.xdStartTime + waitInterval < (new Date()).getTime()){
		this.clearXdInterval();
		var noLoads = "";
		for(var param in this.xdInFlight){
			if(this.xdInFlight[param]){
				noLoads += param + " ";
			}
		}
		dojo.raise("Could not load cross-domain packages: " + noLoads);
	}

	//If any are true, then still waiting.
	//Come back later.	
	for(var param in this.xdInFlight){
		if(this.xdInFlight[param]){
			return;
		}
	}

	//All done loading. Clean up and notify that we are loaded.
	this.clearXdInterval();

	this.xdWalkReqs();

	//Evaluate any packages that were not evaled before.
	//This normally shouldn't happen with proper dojo.provide and dojo.require
	//usage, but providing it just in case. Note that these may not be executed
	//in the original order that the developer intended.
	//Pass dojo in so that later, to support multiple versions of dojo
	//in a page, we can pass which version of dojo to use.
	for(var i = 0; i < this.xdContents.length; i++){
		var current = this.xdContents[i];
		if(current.content && !current.isDefined){
			current.content(dojo);
		}
	}

	//Clean up for the next round of xd loading.
	this.resetXd();

	//Clear inflight count so we will finally do finish work.
	this.inFlightCount = 0; 
	this.callLoaded();
}

dojo.hostenv.flattenRequireArray = function(target){
	//Each result could be an array of 3 elements  (the 3 arguments to dojo.require).
	//We only need the first one.
	if(target){
		for(var i = 0; i < target.length; i++){
			if(target[i] instanceof Array){
				target[i] = {name: target[i][0], content: null};
			}else{
				target[i] = {name: target[i], content: null};
			}
		}
	}
}
