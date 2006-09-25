/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

//	hostenv_svg
if(typeof window == 'undefined'){
	dojo.raise("attempt to use adobe svg hostenv when no window object");
}
dojo.debug = function(){ 
	if (!djConfig.isDebug) { return; }
	var args = arguments;
	var isJUM = dj_global["jum"];
	var s = isJUM ? "": "DEBUG: ";
	for (var i = 0; i < args.length; ++i){ s += args[i]; }
	if (isJUM){ // this seems to be the only way to get JUM to "play nice"
		jum.debug(s);
	} else{ 
		dojo.hostenv.println(s);
	}
};

//	set up dojo.render.
dojo.render.name = navigator.appName;
dojo.render.ver = parseFloat(navigator.appVersion, 10);
switch(navigator.platform){
	case "MacOS":
		dojo.render.os.osx =  true;
		break;
	case "Linux":
		dojo.render.os.linux =  true;
		break;
	case "Windows":
		dojo.render.os.win =  true;
		break;
	default:
		dojo.render.os.linux = true;
		break;
};
dojo.render.svg.capable = true;
dojo.render.svg.support.builtin = true;
//	FIXME the following two is a big-ass hack for now.
dojo.render.svg.moz = ((navigator.userAgent.indexOf("Gecko") >= 0) && (!((navigator.appVersion.indexOf("Konqueror") >= 0) || (navigator.appVersion.indexOf("Safari") >= 0))));
dojo.render.svg.adobe = (window.parseXML != null);

//	agent-specific implementations.

//	from old hostenv_adobesvg.
dojo.hostenv.startPackage("dojo.hostenv");
dojo.hostenv.println = function(s){ 
	try {
		var ti = document.createElement("text");
		ti.setAttribute("x","50");
		ti.setAttribute("y", (25 + 15 * document.getElementsByTagName("text").length));
		ti.appendChild(document.createTextNode(s));
		document.documentElement.appendChild(ti);
	} catch(e){ }
};
dojo.hostenv.name_ = "svg";

//	expected/defined by bootstrap1.js
dojo.hostenv.setModulePrefix = function(module, prefix){ };
dojo.hostenv.getModulePrefix = function(module){ };
dojo.hostenv.getTextStack = [];
dojo.hostenv.loadUriStack = [];
dojo.hostenv.loadedUris = [];
dojo.hostenv.modules_ = {};
dojo.hostenv.modulesLoadedFired = false;
dojo.hostenv.modulesLoadedListeners = [];
dojo.hostenv.getText = function(uri, cb, data){ 
	if (!cb) var cb = function(result){ window.alert(result); };
	if (!data) {
		window.getUrl(uri, cb);
	} else {
		window.postUrl(uri, data, cb);
	}
};
dojo.hostenv.getLibaryScriptUri = function(){ };

dojo.hostenv.loadUri = function(uri){ };
dojo.hostenv.loadUriAndCheck = function(uri, module){ };

//	aliased in loader.js, don't ignore
//	we are going to kill loadModule for the first round of SVG stuff, and include shit manually.
dojo.hostenv.loadModule = function(moduleName){
	//	just like startPackage, but this time we're just checking to make sure it exists already.
	var a = moduleName.split(".");
	var currentObj = window;
	var s = [];
	for (var i = 0; i < a.length; i++){
		if (a[i] == "*") continue;
		s.push(a[i]);
		if (!currentObj[a[i]]){
			dojo.raise("dojo.require('" + moduleName + "'): module does not exist.");
		} else currentObj = currentObj[a[i]];
	}
	return; 
};
dojo.hostenv.startPackage = function(moduleName){
	var a = moduleName.split(".");
	var currentObj = window;
	var s = [];
	for (var i = 0; i < a.length; i++){
		if (a[i] == "*") continue;
		s.push(a[i]);
		if (!currentObj[a[i]]) currentObj[a[i]] = {};
		currentObj = currentObj[a[i]];
	}
	return; 
};

//	wrapper objects for ASVG
if (window.parseXML){
	window.XMLSerialzer = function(){
		//	based on WebFX RichTextControl getXHTML() function.
		function nodeToString(n, a) {
			function fixText(s) { return String(s).replace(/\&/g, "&amp;").replace(/>/g, "&gt;").replace(/</g, "&lt;"); }
			function fixAttribute(s) { return fixText(s).replace(/\"/g, "&quot;"); }
			switch (n.nodeType) {
				case 1:	{	//	ELEMENT
					var name = n.nodeName;
					a.push("<" + name);
					for (var i = 0; i < n.attributes.length; i++) {
						if (n.attributes.item(i).specified) {
							a.push(" " + n.attributes.item(i).nodeName.toLowerCase() + "=\"" + fixAttribute(n.attributes.item(i).nodeValue) + "\"");
						}
					}
					if (n.canHaveChildren || n.hasChildNodes()) {
						a.push(">");
						for (var i = 0; i < n.childNodes.length; i++) nodeToString(n.childNodes.item(i), a);
						a.push("</" + name + ">\n");
					} else a.push(" />\n");
					break;
				}
				case 3: {	//	TEXT
					a.push(fixText(n.nodeValue));
					break;
				}
				case 4: {	//	CDATA
					a.push("<![CDA" + "TA[\n" + n.nodeValue + "\n]" + "]>");
					break;
				}
				case 7:{	//	PROCESSING INSTRUCTION
					a.push(n.nodeValue);
					if (/(^<\?xml)|(^<\!DOCTYPE)/.test(n.nodeValue)) a.push("\n");
					break;
				}
				case 8:{	//	COMMENT
					a.push("<!-- " + n.nodeValue + " -->\n");
					break;
				}
				case 9:		//	DOCUMENT
				case 11:{	//	DOCUMENT FRAGMENT
					for (var i = 0; i < n.childNodes.length; i++) nodeToString(n.childNodes.item(i), a);
					break;
				}
				default:{
					a.push("<!--\nNot Supported:\n\n" + "nodeType: " + n.nodeType + "\nnodeName: " + n.nodeName + "\n-->");
				}
			}
		}
		this.serializeToString = function(node){
			var a = [];
			nodeToString(node, a);
			return a.join("");
		};
	};

	window.DOMParser = function(){
		//	mimetype is basically ignored
		this.parseFromString = function(s){
			return parseXML(s, window.document);
		}
	};

	window.XMLHttpRequest = function(){
		//	we ignore the setting and getting of content-type.
		var uri = null;
		var method = "POST";
		var isAsync = true;	
		var cb = function(d){
			this.responseText = d.content;
			try {
				this.responseXML = parseXML(this.responseText, window.document);
			} catch(e){}
			this.status = "200";
			this.statusText = "OK";
			if (!d.success) {
				this.status = "500";
				this.statusText = "Internal Server Error";
			}
			this.onload();
			this.onreadystatechange();
		};
		this.onload = function(){};
		this.readyState = 4;
		this.onreadystatechange = function(){};
		this.status = 0;
		this.statusText = "";
		this.responseBody = null;
		this.responseStream = null;
		this.responseXML = null;
		this.responseText = null;
		this.abort = function(){ return; };
		this.getAllResponseHeaders = function(){ return []; };
		this.getResponseHeader = function(n){ return null; };
		this.setRequestHeader = function(nm, val){ };
		this.open = function(meth, url, async){ 
			method = meth;
			uri = url;
		};
		this.send = function(data){
			var d = data || null;
			if (method == "GET") getURL(uri, cb);
			else postURL(uri, data, cb);
		};
	};
}
