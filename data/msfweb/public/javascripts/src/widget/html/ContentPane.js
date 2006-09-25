/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.ContentPane");

dojo.require("dojo.widget.*");
dojo.require("dojo.io.*");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.widget.ContentPane");
dojo.require("dojo.string");
dojo.require("dojo.string.extras");
dojo.require("dojo.style");

dojo.widget.html.ContentPane = function(){
	this._onLoadStack = [];
	this._onUnLoadStack = [];
	dojo.widget.HtmlWidget.call(this);
}
dojo.inherits(dojo.widget.html.ContentPane, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.html.ContentPane, {
	widgetType: "ContentPane",
	isContainer: true,

	// remote loading options
	adjustPaths: true,
	href: "",
	extractContent: true,
	parseContent: true,
	cacheContent: true,
	preload: false,			// force load of data even if pane is hidden
	refreshOnShow: false,
	handler: "",			// generate pane content from a java function
	executeScripts: false,	// if true scripts in content will be evaled after content is set and parsed
	scriptScope: null,		// scopeContainer for downloaded scripts

		// If the user want a global in the remote script he/she just omitts the var
		// examples:
		//--------------------------
		// these gets collected by scriptScope and is reached by dojo.widget.byId('..').scriptScope.myCustomproperty
		//	this.myString = "dojo is a great javascript toolkit!";
		//
		//	this.alertMyString = function(){
		//		alert(myString);
		//	}
		// -------------------------
		// these go into the global namespace (window) notice lack of var, equiv to window.myString
		//	myString = "dojo is a javascript toolkit!";
		//
		//	alertMyString = function(){
		//		alert(myString);
		// }


	// private
	_remoteStyles: null,	// array of stylenodes inserted to document head
							// by remote content, used when we clean up for new content

	_callOnUnLoad: false,		// used by setContent and _handleDefults, makes sure onUnLoad is only called once

	postCreate: function(args, frag, parentComp){
		if ( this.handler != "" ){
			this.setHandler(this.handler);
		}
		if(this.isShowing()||this.preload){ this.loadContents(); }
	},

	show: function(){
		// if refreshOnShow is true, reload the contents every time; otherwise, load only the first time
		if(this.refreshOnShow){
			this.refresh();
		}else{
			this.loadContents();
		}
		dojo.widget.html.ContentPane.superclass.show.call(this);
	},

	refresh: function(){
		this.isLoaded=false;
		this.loadContents();
	},

	loadContents: function() {
		if ( this.isLoaded ){
			return;
		}
		this.isLoaded=true;
		if ( dojo.lang.isFunction(this.handler)) {
			this._runHandler();
		} else if ( this.href != "" ) {
			this._downloadExternalContent(this.href, this.cacheContent);
		}
	},

	
	setUrl: function(/*String*/ url) {
		// summary:
		// 	Reset the (external defined) content of this pane and replace with new url
		this.href = url;
		this.isLoaded = false;
		if ( this.preload || this.isShowing() ){
			this.loadContents();
		}
	},

	_downloadExternalContent: function(url, useCache) {
		this._handleDefaults("Loading...", "onDownloadStart");
		var self = this;
		dojo.io.bind({
			url: url,
			useCache: useCache,
			preventCache: !useCache,
			mimetype: "text/html",
			handler: function(type, data, e) {
				if(type == "load") {
					self.onDownloadEnd.call(self, url, data);
				} else {
					// works best when from a live server instead of from file system 
					self._handleDefaults.call(self, "Error loading '" + url + "' (" + e.status + " "+  e.statusText + ")", "onDownloadError");
					self.onLoad();
				}
			}
		});
	},

	// called when setContent is finished
	onLoad: function(e){
		this._runStack("_onLoadStack");
	},

	// called before old content is cleared
	onUnLoad: function(e){
		this._runStack("_onUnLoadStack");
		this.scriptScope = null;
	},

	_runStack: function(stName){
		var st = this[stName]; var err = "";
		for(var i = 0;i < st.length; i++){
			try{
				st[i].call(this.scriptScope);
			}catch(e){ 
				err += "\n"+st[i]+" failed: "+e.description;
			}
		}
		this[stName] = [];

		if(err.length){
			var name = (stName== "_onLoadStack") ? "addOnLoad" : "addOnUnLoad";
			this._handleDefaults(name+" failure\n "+err, "onExecError", true);
		}
	},

	addOnLoad: function(obj, func){
		// summary
		// 	same as to dojo.addOnLoad but does not take "function_name" as a string
		this._pushOnStack(this._onLoadStack, obj, func);
	},

	addOnUnLoad: function(obj, func){
		// summary
		// 	same as to dojo.addUnOnLoad but does not take "function_name" as a string
		this._pushOnStack(this._onUnLoadStack, obj, func);
	},

	_pushOnStack: function(stack, obj, func){
		if(typeof func == 'undefined') {
			stack.push(obj);
		}else{
			stack.push(function(){ obj[func](); });
		}
	},

	destroy: function(){
		// make sure we call onUnLoad
		this.onUnLoad();
		dojo.widget.html.ContentPane.superclass.destroy.call(this);
	},

	// called when content script eval error or Java error occurs, preventDefault-able
	onExecError: function(e){ /*stub*/ },

	// called on DOM faults, require fault etc in content, preventDefault-able
	onContentError: function(e){ /*stub*/ },

	// called when download error occurs, preventDefault-able
	onDownloadError: function(e){ /*stub*/ },

	// called before download starts, preventDefault-able
	onDownloadStart: function(e){ /*stub*/ },

	// called when download is finished
	onDownloadEnd: function(url, data){
		data = this.splitAndFixPaths(data, url);
		this.setContent(data);
	},

	// usefull if user wants to prevent default behaviour ie: _setContent("Error...")
	_handleDefaults: function(e, handler, useAlert){
		if(!handler){ handler = "onContentError"; }
		if(dojo.lang.isString(e)){
			e = {
				"text": e,
				"toString": function(){ return this.text; }
			}
		}
		if(typeof e.returnValue != "boolean"){
			e.returnValue = true; 
		}
		if(typeof e.preventDefault != "function"){
			e.preventDefault = function(){
				this.returnValue = false;
			}
		}
		// call our handler
		this[handler](e);
		if(e.returnValue){
			if(useAlert){
				alert(e.toString());
			}else{
				if(this._callOnUnLoad){
					this.onUnLoad(); // makes sure scripts can clean up after themselves, before we setContent
				}
				this._callOnUnLoad = false; // makes sure we dont try to call onUnLoad again on this event,
											// ie onUnLoad before 'Loading...' but not before clearing 'Loading...'
				this._setContent(e.toString());
			}
		}
	},

	
	splitAndFixPaths: function(/*String*/s, /*dojo.uri.Uri?*/url){
		// summary:
		// 	fixes all remote paths in (hopefully) all cases for example images, remote scripts, links etc.
		// 	splits up content in different pieces, scripts, title, style, link and whats left becomes .xml

		if(!url) { url = "./"; } // point to this page if not set
		if(!s) { return ""; }

		// fix up paths in data
		var titles = []; var scripts = []; var linkStyles = [];
		var styles = []; var remoteScripts = []; var requires = [];

		// khtml is much more picky about dom faults, you can't for example attach a style node under body of document
		// must go into head, as does a title node, so we need to cut out those tags
		// cut out title tags
		var match = [];
		while(match){
			match = s.match(/<title[^>]*>([\s\S]*?)<\/title>/i); // can't match with dot as that 
			if(!match){ break;}					//doesnt match newline in js
			titles.push(match[1]);
			s = s.replace(/<title[^>]*>[\s\S]*?<\/title>/i, "");
		}

		// cut out <style> url(...) </style>, as that bails out in khtml
		var match = [];
		while(match){
			match = s.match(/<style[^>]*>([\s\S]*?)<\/style>/i);
			if(!match){ break; }
			styles.push(dojo.style.fixPathsInCssText(match[1], url));
			s = s.replace(/<style[^>]*?>[\s\S]*?<\/style>/i, "");
		}

		// attributepaths one tag can have multiple paths example:
		// <input src="..." style="url(..)"/> or <a style="url(..)" href="..">
		// strip out the tag and run fix on that.
		// this guarantees that we won't run replace another tag's attribute + it was easier do
		var pos = 0; var pos2 = 0; var stop = 0 ;var str = ""; var fixedPath = "";
		var attr = []; var fix = ""; var tagFix = ""; var tag = ""; var regex = ""; 
		while(pos>-1){
			pos = s.search(/<[a-z][a-z0-9]*[^>]*\s(?:(?:src|href|style)=[^>])+[^>]*>/i);
			if(pos==-1){ break; }
			str += s.substring(0, pos);
			s = s.substring(pos, s.length);
			tag = s.match(/^<[a-z][a-z0-9]*[^>]*>/i)[0];
			s = s.substring(tag.length, s.length);

			// loop through attributes
			pos2 = 0; tagFix = ""; fix = ""; regex = ""; var regexlen = 0;
			while(pos2!=-1){
				// slices up before next attribute check, values from previous loop
				tagFix += tag.substring(0, pos2) + fix;
				tag = tag.substring(pos2+regexlen, tag.length);

				// fix next attribute or bail out when done
				// hopefully this charclass covers most urls
				attr = tag.match(/ (src|href|style)=(['"]?)([\w()\[\]\/.,\\'"-:;#=&?\s@]+?)\2/i);
				if(!attr){ break; }

				switch(attr[1].toLowerCase()){
					case "src":// falltrough
					case "href":
						// this hopefully covers most common protocols
						if(attr[3].search(/^(?:[#]|(?:(?:https?|ftps?|file|javascript|mailto|news):))/)==-1){
							fixedPath = (new dojo.uri.Uri(url, attr[3]).toString());
						} else {
							pos2 = pos2 + attr[3].length;
							continue;
						}
						break;
					case "style":// style
						fixedPath = dojo.style.fixPathsInCssText(attr[3], url);
						break;
					default:
						pos2 = pos2 + attr[3].length;
						continue;
				}

				regex = " " + attr[1] + "=" + attr[2] + attr[3] + attr[2];
				regexlen = regex.length;
				fix = " " + attr[1] + "=" + attr[2] + fixedPath + attr[2];
				pos2 = tag.search(new RegExp(dojo.string.escapeRegExp(regex)));
			}
			str += tagFix + tag;
			pos = 0; // reset for next mainloop
		}
		s = str+s;

		// cut out all script tags, push them into scripts array
		match = []; var tmp = [];
		while(match){
			match = s.match(/<script([^>]*)>([\s\S]*?)<\/script>/i);
			if(!match){ break; }
			if(match[1]){
				attr = match[1].match(/src=(['"]?)([^"']*)\1/i);
				if(attr){
					// remove a dojo.js or dojo.js.uncompressed.js from remoteScripts
					// we declare all files with dojo.js as bad, regardless of folder
					var tmp = attr[2].search(/.*(\bdojo\b(?:\.uncompressed)?\.js)$/);
					if(tmp > -1){
						dojo.debug("Security note! inhibit:"+attr[2]+" from  beeing loaded again.");
					}else{
						remoteScripts.push(attr[2]);
					}
				}
			}
			if(match[2]){
				// strip out all djConfig variables from script tags nodeValue
				// this is ABSOLUTLY needed as reinitialize djConfig after dojo is initialised
				// makes a dissaster greater than Titanic, update remove writeIncludes() to
				var sc = match[2].replace(/(?:var )?\bdjConfig\b(?:[\s]*=[\s]*\{[^}]+\}|\.[\w]*[\s]*=[\s]*[^;\n]*)?;?|dojo\.hostenv\.writeIncludes\(\s*\);?/g, "");
				if(!sc){ continue; }

				// cut out all dojo.require (...) calls, if we have execute 
				// scripts false widgets dont get there require calls
				// does suck out possible widgetpackage registration as well
				tmp = [];
				while(tmp && requires.length<100){
					tmp = sc.match(/dojo\.(?:(?:require(?:After)?(?:If)?)|(?:widget\.(?:manager\.)?registerWidgetPackage)|(?:(?:hostenv\.)?setModulePrefix))\((['"]).*?\1\)\s*;?/);
					if(!tmp){ break;}
					requires.push(tmp[0]);
					sc = sc.replace(tmp[0], "");
				}
				scripts.push(sc);
			}
			s = s.replace(/<script[^>]*>[\s\S]*?<\/script>/i, "");
		}

		// scan for scriptScope in html eventHandlers and replace with link to this pane
		if(this.executeScripts){
			var regex = /(<[a-zA-Z][a-zA-Z0-9]*\s[^>]*\S=(['"])[^>]*[^\.\]])scriptScope([^>]*>)/;
			var pos = 0;var str = "";match = [];var cit = "";
			while(pos > -1){
				pos = s.search(regex);
				if(pos > -1){
					cit = ((RegExp.$2=="'") ? '"': "'");
					str += s.substring(0, pos);
					s = s.substr(pos).replace(regex, "$1dojo.widget.byId("+ cit + this.widgetId + cit + ").scriptScope$3");
				}
			}
			s = str + s;
		}

		// cut out all <link rel="stylesheet" href="..">
		match = [];
		while(match){
			match = s.match(/<link ([^>]*rel=['"]?stylesheet['"]?[^>]*)>/i);
			if(!match){ break; }
			attr = match[1].match(/href=(['"]?)([^'">]*)\1/i);
			if(attr){
				linkStyles.push(attr[2]);
			}
			s = s.replace(new RegExp(match[0]), "");
		}

		return {"xml": s, // Object
			"styles": styles,
			"linkStyles": linkStyles,
			"titles": titles,
			"requires": 	requires,
			"scripts": scripts,
			"remoteScripts": remoteScripts,
			"url": url};
	},

	
	_setContent: function(/*String*/ xml){
		// summary: 
		//		private internal function without path regExpCheck and no onLoad calls aftervards

		// remove old children from current content
		this.destroyChildren();

		// remove old stylenodes from HEAD
		if(this._remoteStyles){
			for(var i = 0; i < this._remoteStyles.length; i++){
				if(this._remoteStyles[i] && this._remoteStyles.parentNode){
					this._remoteStyles[i].parentNode.removeChild(this._remoteStyles[i]);
				}
			}
			this._remoteStyles = null;
		}

		var node = this.containerNode || this.domNode;
		try{
			if(typeof xml != "string"){
				node.innerHTML = "";
				node.appendChild(xml);
			}else{
				node.innerHTML = xml;
			}
		} catch(e){
			e = "Could'nt load content:"+e;
			this._handleDefaults(e, "onContentError");
		}
	},

	setContent: function(/*String*/ data){
		// summary:
		// 	Destroys old content and setting new content, and possibly initialize any widgets within 'data'

		if(this._callOnUnLoad){ // this tells a remote script clean up after itself
			this.onUnLoad();
		}
		this._callOnUnLoad = true;

		if(!data || dojo.dom.isNode(data)){
			// if we do a clean using setContent(""); or setContent(#node) bypass all parseing, extractContent etc
			this._setContent(data);
			this.onResized();
			this.onLoad();
		}else{
			// need to run splitAndFixPaths? ie. manually setting content
			 if((!data.xml)&&(this.adjustPaths)){
				data = this.splitAndFixPaths(data);
			}
			if(this.extractContent) {
				var matches = data.xml.match(/<body[^>]*>\s*([\s\S]+)\s*<\/body>/im);
				if(matches) { data.xml = matches[1]; }
			}
			// insert styleNodes, from <style>....
			for(var i = 0; i < data.styles.length; i++){
				if(i==0){ 
					this._remoteStyles = []; 
				}
				this._remoteStyles.push(dojo.style.insertCssText(data.styles[i]));
			}
			// insert styleNodes, from <link href="...">
			for(var i = 0; i < data.linkStyles.length; i++){
				if(i==0){ 
					this._remoteStyles = []; 
				}
				this._remoteStyles.push(dojo.style.insertCssFile(data.linkStyles[i]));
			}
			this._setContent(data.xml);

			if(this.parseContent){
				for(var i = 0; i < data.requires.length; i++){
					try{ 
						eval(data.requires[i]);
					} catch(e){
						this._handleDefaults(e, "onContentError", true);
					}
				}
			}
			// need to allow async load, Xdomain uses it
			// is inline function because we cant send args to addOnLoad function
			var _self = this;
			function asyncParse(){
				if(_self.executeScripts){
					_self._executeScripts(data);
				}

				if(_self.parseContent){
					var node = _self.containerNode || _self.domNode;
					var parser = new dojo.xml.Parse();
					var frag = parser.parseElement(node, null, true);
					// createSubComponents not createComponents because frag has already been created
					dojo.widget.getParser().createSubComponents(frag, _self);
				}

				_self.onResized();
				_self.onLoad();
			}
			// try as long as possible to make setContent sync call
			if(dojo.hostenv.isXDomain && data.requires.length){
				dojo.addOnLoad(asyncParse);
			}else{
				asyncParse();
			}
		}
	},

	// Generate pane content from given java function
	setHandler: function(handler) {
		var fcn = dojo.lang.isFunction(handler) ? handler : window[handler];
		if(!dojo.lang.isFunction(fcn)) {
			// FIXME: needs testing! somebody with java knowledge needs to try this
			this._handleDefaults("Unable to set handler, '" + handler + "' not a function.", "onExecError", true);
			return;
		}
		this.handler = function() {
			return fcn.apply(this, arguments);
		}
	},

	_runHandler: function() {
		if(dojo.lang.isFunction(this.handler)) {
			this.handler(this, this.domNode);
			return false;
		}
		return true;
	},

	_executeScripts: function(data) {
		// do remoteScripts first
		var self = this;
		for(var i = 0; i < data.remoteScripts.length; i++){
			dojo.io.bind({
				"url": data.remoteScripts[i],
				"useCash":	this.cacheContent,
				"load":     function(type, scriptStr){
						dojo.lang.hitch(self, data.scripts.push(scriptStr));
				},
				"error":    function(type, error){
						self._handleDefaults.call(self, type + " downloading remote script", "onExecError", true);
				},
				"mimetype": "text/plain",
				"sync":     true
			});
		}

		var scripts = "";
		for(var i = 0; i < data.scripts.length; i++){
			scripts += data.scripts[i];
		}

		try{
			// initialize a new anonymous container for our script, dont make it part of this widgets scope chain
			// instead send in a variable that points to this widget, usefull to connect events to onLoad, onUnLoad etc..
			this.scriptScope = null;
			this.scriptScope = new (new Function('_container_', scripts+'; return this;'))(self);
		}catch(e){
			this._handleDefaults("Error running scripts from content:\n"+e, "onExecError", true);
		}
	}
});

dojo.widget.tags.addParseTreeHandler("dojo:ContentPane");
