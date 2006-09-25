/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.doc");
dojo.require("dojo.io.*");
dojo.require("dojo.event.topic");
dojo.require("dojo.rpc.JotService");
dojo.require("dojo.dom");

/*
 * TODO:
 *
 * Package summary needs to compensate for "is"
 * Handle host environments
 * Deal with dojo.widget weirdness
 * Parse parameters
 * Limit function parameters to only the valid ones (Involves packing parameters onto meta during rewriting)
 * Package display page
 *
 */

dojo.doc._count = 0;
dojo.doc._keys = {};
dojo.doc._myKeys = [];
dojo.doc._callbacks = {function_names: []};
dojo.doc._cache = {}; // Saves the JSON objects in cache
dojo.doc._rpc = new dojo.rpc.JotService;
dojo.doc._rpc.serviceUrl = "http://dojotoolkit.org/~pottedmeat/jsonrpc.php";

dojo.lang.mixin(dojo.doc, {
	functionNames: function(/*mixed*/ selectKey, /*Function*/ callback){
		// summary: Returns an ordered list of package and function names.
		dojo.debug("functionNames()");
		if(!selectKey){
			selectKey = ++dojo.doc._count;
		}
		dojo.doc._buildCache({
			type: "function_names",
			callbacks: [dojo.doc._functionNames, callback],
			selectKey: selectKey
		});
	},

	_functionNames: function(/*String*/ type, /*Array*/ data, /*Object*/ evt){
		dojo.debug("_functionNames()");
		var searchData = [];
		for(var key in data){
			// Add the package if it doesn't exist in its children
			if(!dojo.lang.inArray(data[key], key)){
				searchData.push([key, key]);
			}
			// Add the functions
			for(var pkg_key in data[key]){
				searchData.push([data[key][pkg_key], data[key][pkg_key]]);
			}
		}

		searchData = searchData.sort(dojo.doc._sort);

		if(evt.callbacks && evt.callbacks.length){
			var callback = evt.callbacks.shift();
			callback.call(null, type, searchData, evt);
		}
	},

	getMeta: function(/*mixed*/ selectKey, /*Function*/ callback, /*Function*/ name, /*String?*/ id){
		// summary: Gets information about a function in regards to its meta data
		dojo.debug("getMeta(" + name + ")");
		if(!selectKey){
			selectKey = ++dojo.doc._count;
		}
		dojo.doc._buildCache({
			type: "meta",
			callbacks: [callback],
			name: name,
			id: id,
			selectKey: selectKey
		});
	},

	_getMeta: function(/*String*/ type, /*Object*/ data, /*Object*/ evt){
		dojo.debug("_getMeta(" + evt.name + ") has package: " + evt.pkg + " with: " + type);
		if("load" == type && evt.pkg){
			evt.type = "meta";
			dojo.doc._buildCache(evt);
		}else{
			if(evt.callbacks && evt.callbacks.length){
				var callback = evt.callbacks.shift();
				callback.call(null, "error", {}, evt);
			}
		}
	},

	getSrc: function(/*mixed*/ selectKey, /*Function*/ callback, /*String*/ name, /*String?*/ id){
		// summary: Gets src file (created by the doc parser)
		dojo.debug("getSrc()");
		if(!selectKey){
			selectKey = ++dojo.doc._count;
		}	
		dojo.doc._buildCache({
			type: "src",
			callbacks: [callback],
			name: name,
			id: id,
			selectKey: selectKey
		});
	},

	_getSrc: function(/*String*/ type, /*Object*/ data, /*Object*/ evt){
		dojo.debug("_getSrc()");
		if(evt.pkg){	
			evt.type = "src";
			dojo.doc._buildCache(evt);
		}else{
			if(evt.callbacks && evt.callbacks.length){
				var callback =  evt.callbacks.shift();
				callback.call(null, "error", {}, evt);
			}
		}
	},

	getDoc: function(/*mixed*/ selectKey, /*Function*/ callback, /*String*/ name, /*String?*/ id){
		// summary: Gets external documentation stored on jot
		dojo.debug("getDoc()");
		if(!selectKey){
			selectKey = ++dojo.doc._count;
		}
		var input = {
			type: "doc",
			callbacks: [callback],
			name: name,
			id: id,
			selectKey: selectKey
		}
		dojo.doc.functionPackage(dojo.doc._getDoc, input);
	},

	_getDoc: function(/*String*/ type, /*Object*/ data, /*Object*/ evt){
		dojo.debug("_getDoc(" + evt.pkg + "/" + evt.name + ")");
	
		dojo.doc._keys[evt.selectKey] = {count: 0};

		var search = {};
		search.forFormName = "DocFnForm";
		search.limit = 1;

		if(!evt.id){
			search.filter = "it/DocFnForm/require = '" + evt.pkg + "' and it/DocFnForm/name = '" + evt.name + "' and not(it/DocFnForm/id)";
		}else{
			search.filter = "it/DocFnForm/require = '" + evt.pkg + "' and it/DocFnForm/name = '" + evt.name + "' and it/DocFnForm/id = '" + evt.id + "'";
		}
		dojo.debug(dojo.json.serialize(search));
	
		dojo.doc._rpc.callRemote("search", search).addCallbacks(function(data){ evt.type = "fn"; dojo.doc._gotDoc("load", data.list[0], evt); }, function(data){ evt.type = "fn"; dojo.doc._gotDoc("error", {}, evt); });
	
		search.forFormName = "DocParamForm";

		if(!evt.id){
			search.filter = "it/DocParamForm/fns = '" + evt.pkg + "=>" + evt.name + "'";
		}else{
			search.filter = "it/DocParamForm/fns = '" + evt.pkg + "=>" + evt.name + "=>" + evt.id + "'";
		}
		delete search.limit;

		dojo.doc._rpc.callRemote("search", search).addCallbacks(function(data){ evt.type = "param"; dojo.doc._gotDoc("load", data.list, evt); }, function(data){ evt.type = "param"; dojo.doc._gotDoc("error", {}, evt); });
	},

	_gotDoc: function(/*String*/ type, /*Array*/ data, /*Object*/ evt){
		dojo.debug("_gotDoc(" + evt.type + ") for " + evt.selectKey);
		dojo.doc._keys[evt.selectKey][evt.type] = data;
		if(++dojo.doc._keys[evt.selectKey].count == 2){
			dojo.debug("_gotDoc() finished");
			var keys = dojo.doc._keys[evt.selectKey];
			var description = '';
			if(!keys.fn){
				keys.fn = {}
			}
			if(keys.fn["main/text"]){
				description = dojo.dom.createDocumentFromText(keys.fn["main/text"]).childNodes[0].innerHTML;
				if(!description){
					description = keys.fn["main/text"];
				}			
			}
			data = {
				description: description,
				returns: keys.fn["DocFnForm/returns"],
				id: keys.fn["DocFnForm/id"],
				parameters: {},
				variables: []
			}
			for(var i = 0, param; param = keys["param"][i]; i++){
				data.parameters[param["DocParamForm/name"]] = {
					description: param["DocParamForm/desc"]
				};
			}

			delete dojo.doc._keys[evt.selectKey];
		
			if(evt.callbacks && evt.callbacks.length){
				var callback = evt.callbacks.shift();
				callback.call(null, "load", data, evt);
			}
		}
	},

	getPkgMeta: function(/*mixed*/ selectKey, /*Function*/ callback, /*String*/ name){
		dojo.debug("getPkgMeta(" + name + ")");
		if(!selectKey){
			selectKey = ++dojo.doc._count;
		}
		dojo.doc._buildCache({
			type: "pkgmeta",
			callbacks: [callback],
			name: name,
			selectKey: selectKey
		});
	},

	_getPkgMeta: function(/*Object*/ input){
		dojo.debug("_getPkgMeta(" + input.name + ")");
		input.type = "pkgmeta";
		dojo.doc._buildCache(input);
	},

	_onDocSearch: function(/*Object*/ input){
		dojo.debug("_onDocSearch(" + input.name + ")");
		if(!input.name){
			return;
		}
		if(!input.selectKey){
			input.selectKey = ++dojo.doc._count;
		}
		input.callbacks = [dojo.doc._onDocSearchFn];
		input.name = input.name.toLowerCase();
		input.type = "function_names";

		dojo.doc._buildCache(input);
	},

	_onDocSearchFn: function(/*String*/ type, /*Array*/ data, /*Object*/ evt){
		dojo.debug("_onDocSearchFn(" + evt.name + ")");
		var packages = [];
		var size = 0;
		pkgLoop:
		for(var pkg in data){
			for(var i = 0, fn; fn = data[pkg][i]; i++){
				if(fn.toLowerCase().indexOf(evt.name) != -1){
					// Build a list of all packages that need to be loaded and their loaded state.
					++size;
					packages.push(pkg);
					continue pkgLoop;
				}
			}
		}
		dojo.doc._keys[evt.selectKey] = {};
		dojo.doc._keys[evt.selectKey].pkgs = packages;
		dojo.doc._keys[evt.selectKey].pkg = evt.name; // Remember what we were searching for
		dojo.doc._keys[evt.selectKey].loaded = 0;
		for(var i = 0, pkg; pkg = packages[i]; i++){
			setTimeout("dojo.doc.getPkgMeta(\"" + evt.selectKey + "\", dojo.doc._onDocResults, \"" + pkg + "\");", i*10);
		}
	},

	_onDocResults: function(/*String*/ type, /*Object*/ data, /*Object*/ evt){
		dojo.debug("_onDocResults(" + evt.name + "/" + dojo.doc._keys[evt.selectKey].pkg + ") " + type);
		++dojo.doc._keys[evt.selectKey].loaded;

		if(dojo.doc._keys[evt.selectKey].loaded == dojo.doc._keys[evt.selectKey].pkgs.length){
			var info = dojo.doc._keys[evt.selectKey];
			var pkgs = info.pkgs;
			var name = info.pkg;
			delete dojo.doc._keys[evt.selectKey];
			var results = {selectKey: evt.selectKey, docResults: []};
			data = dojo.doc._cache;

			for(var i = 0, pkg; pkg = pkgs[i]; i++){
				if(!data[pkg]){
					continue;
				}
				for(var fn in data[pkg]["meta"]){
					if(fn.toLowerCase().indexOf(name) == -1){
						continue;
					}
					if(fn != "requires"){
						for(var pId in data[pkg]["meta"][fn]){
							var result = {
								pkg: pkg,
								name: fn,
								summary: ""
							}
							if(data[pkg]["meta"][fn][pId].summary){
								result.summary = data[pkg]["meta"][fn][pId].summary;
							}
							results.docResults.push(result);
						}
					}
				}
			}

			dojo.debug("Publishing docResults");
			dojo.doc._printResults(results);
		}
	},
	
	_printResults: function(results){
		dojo.debug("_printResults(): called");
		// summary: Call this function to send the /doc/results topic
	},

	_onDocSelectFunction: function(/*Object*/ input){
		// summary: Get doc, meta, and src
		var name = input.name;
		var selectKey = selectKey;
		dojo.debug("_onDocSelectFunction(" + name + ")");
		if(!name){
			return false;
		}
		if(!selectKey){
			selectKey = ++dojo.doc._count;
		}

		dojo.doc._keys[selectKey] = {size: 0};
		dojo.doc._myKeys[++dojo.doc._count] = {selectKey: selectKey, type: "meta"}
		dojo.doc.getMeta(dojo.doc._count, dojo.doc._onDocSelectResults, name);
		dojo.doc._myKeys[++dojo.doc._count] = {selectKey: selectKey, type: "src"}
		dojo.doc.getSrc(dojo.doc._count, dojo.doc._onDocSelectResults, name);
		dojo.doc._myKeys[++dojo.doc._count] = {selectKey: selectKey, type: "doc"}
		dojo.doc.getDoc(dojo.doc._count, dojo.doc._onDocSelectResults, name);
	},

	_onDocSelectResults: function(/*String*/ type, /*Object*/ data, /*Object*/ evt){
		dojo.debug("dojo.doc._onDocSelectResults(" + evt.type + ", " + evt.name + ")");
		var myKey = dojo.doc._myKeys[evt.selectKey];
		dojo.doc._keys[myKey.selectKey][myKey.type] = data;
		dojo.doc._keys[myKey.selectKey].size;
		if(++dojo.doc._keys[myKey.selectKey].size == 3){
			var key = dojo.lang.mixin(evt, dojo.doc._keys[myKey.selectKey]);
			delete key.size;
			dojo.debug("Publishing docFunctionDetail");
			dojo.doc._printFunctionDetail(key);
			delete dojo.doc._keys[myKey.selectKey];
			delete dojo.doc._myKeys[evt.selectKey];
		}
	},
	
	_printFunctionDetail: function(results) {
		// summary: Call this function to send the /doc/functionDetail topic event
	},

	_buildCache: function(/*Object*/ input){
		var type = input.type;
		var pkg = input.pkg;
		var callbacks = input.callbacks;
		var id = input.id;
		if(!id){
			id = "_";
		}
		var name = input.name;
	
		dojo.debug("_buildCache() type: " + type);
		if(type == "function_names"){
			if(!dojo.doc._cache["function_names"]){
				dojo.debug("_buildCache() new cache");
				if(callbacks && callbacks.length){
					dojo.doc._callbacks.function_names.push([input, callbacks.shift()]);
				}
				dojo.doc._cache["function_names"] = {loading: true};
				dojo.io.bind({
					url: "json/function_names",
					mimetype: "text/json",
					error: function(type, data, evt){
						dojo.debug("Unable to load function names");
						for(var i = 0, callback; callback = dojo.doc._callbacks.function_names[i]; i++){
							callback[1].call(null, "error", {}, callback[0]);
						}
					},
					load: function(type, data, evt){
						dojo.doc._cache['function_names'] = data;
						for(var i = 0, callback; callback = dojo.doc._callbacks.function_names[i]; i++){
							callback[1].call(null, "load", data, callback[0]);
						}
					}
				});
			}else if(dojo.doc._cache["function_names"].loading){
				dojo.debug("_buildCache() loading cache");
				if(callbacks && callbacks.length){
					dojo.doc._callbacks.function_names.push([input, callbacks.shift()]);
				}
			}else{
				dojo.debug("_buildCache() from cache");
				if(callbacks && callbacks.length){
					var callback = callbacks.shift();
					callback.call(null, "load", dojo.doc._cache["function_names"], input);
				}
			}
		}else if(type == "meta" || type == "src"){
			if(!pkg){
				if(type == "meta"){
					dojo.doc.functionPackage(dojo.doc._getMeta, input);
				}else{
					dojo.doc.functionPackage(dojo.doc._getSrc, input);
				}
			}else{
				try{
					var cached = dojo.doc._cache[pkg][name][id][type];
				}catch(e){}

				if(cached){
					if(callbacks && callbacks.length){
						var callback = callbacks.shift();
						callback.call(null, "load", cached, input);
						return;
					}
				}

				dojo.debug("Finding " + type + " for: " + pkg + ", function: " + name + ", id: " + id);

				var mimetype = "text/json";
				if(type == "src"){
					mimetype = "text/plain"
				}

				var url = "json/" + pkg + "/" + name + "/" + id + "/" + type;

				dojo.io.bind({
					url: url,
					input: input,
					mimetype: mimetype,
					error: function(type, data, evt, args){
						var input = args.input;
						var pkg = input.pkg;
						var type = input.type;
						var callbacks = input.callbacks;
						var id = input.id;
						var name = input.name;

						if(callbacks && callbacks.length){
							if(!data){
								data = {};
							}
							if(!dojo.doc._cache[pkg]){
								dojo.doc._cache[pkg] = {};
							}
							if(!dojo.doc._cache[pkg][name]){
								dojo.doc._cache[pkg][name] = {};
							}
							if(type == "meta"){
								data.sig = dojo.doc._cache[pkg][name][id].sig;
								data.params = dojo.doc._cache[pkg][name][id].params;
							}
							var callback = callbacks.shift();
							callback.call(null, "error", data, args.input);
						}
					},
					load: function(type, data, evt, args){
						var input = args.input;
						var pkg = input.pkg;
						var type = input.type;
						var id = input.id;
						var name = input.name;
						var cache = dojo.doc._cache;
						dojo.debug("_buildCache() loaded " + type);

						if(!data){
							data = {};
						}
						if(!cache[pkg]){
							dojo.doc._cache[pkg] = {};
						}
						if(!cache[pkg][name]){
							dojo.doc._cache[pkg][name] = {};
						}
						if(!cache[pkg][name][id]){
							dojo.doc._cache[pkg][name][id] = {};
						}
						if(!cache[pkg][name][id].meta){
							dojo.doc._cache[pkg][name][id].meta = {};
						}
						dojo.doc._cache[pkg][name][id][type] = data;
						if(callbacks && callbacks.length){
							var callback = callbacks.shift();
							callback.call(null, "load", data, args.input);
						}
					}
				});
			}
		}else if(type == "pkgmeta"){
			try{
				var cached = dojo.doc._cache[name]["meta"];
			}catch(e){}

			if(cached){
				if(callbacks && callbacks.length){
					var callback = callbacks.shift();
					callback.call(null, "load", cached, input);
					return;
				}
			}

			dojo.debug("Finding package meta for: " + name);

			dojo.io.bind({
				url: "json/" + name + "/meta",
				input: input,
				mimetype: "text/json",
				error: function(type, data, evt, args){
					var callbacks = args.input.callbacks;
					if(callbacks && callbacks.length){
						var callback = callbacks.shift();
						callback.call(null, "error", {}, args.input);
					}
				},
				load: function(type, data, evt, args){
					var pkg = args.input.name;
					var cache = dojo.doc._cache;

					dojo.debug("_buildCache() loaded for: " + pkg);
					if(!cache[pkg]){
						dojo.doc._cache[pkg] = {};
					}
				
					if(!cache[pkg]["meta"]){
						dojo.doc._cache[pkg]["meta"] = {};
					}
				
					var methods = data.methods;
					if(methods){
						for(var method in methods){
							if (method == "is") {
								continue;
							}
							for(var pId in methods[method]){
								if(!cache[pkg]["meta"][method]){
									dojo.doc._cache[pkg]["meta"][method] = {};
								}
								if(!cache[pkg]["meta"][method][pId]){
									dojo.doc._cache[pkg]["meta"][method][pId] = {};
								}
								dojo.doc._cache[pkg]["meta"][method][pId].summary = methods[method][pId];
							}
						}
					}

					dojo.doc._cache[pkg]["meta"].methods = methods;
					var requires = data.requires;
					if(requires){
						dojo.doc._cache[pkg]["meta"].requires = requires;
					}
					if(callbacks && callbacks.length){
						var callback = callbacks.shift();
						callback.call(null, "load", methods, input);
					}
				}
			});
		}
	},

	selectFunction: function(/*String*/ name, /*String?*/ id){
		// summary: The combined information
	},

	savePackage: function(/*String*/ name, /*String*/ description){
		dojo.doc._rpc.callRemote(
			"saveForm",
			{
				form: "DocPkgForm",
				path: "/WikiHome/DojoDotDoc/id",
				pname1: "main/text",
				pvalue1: "Test"
			}
		).addCallbacks(dojo.doc._results, dojo.doc._results);
	},

	functionPackage: function(/*Function*/ callback, /*Object*/ input){
		dojo.debug("functionPackage() name: " + input.name + " for type: " + input.type);
		input.type = "function_names";
		input.callbacks.unshift(callback);
		input.callbacks.unshift(dojo.doc._functionPackage);
		dojo.doc._buildCache(input);
	},

	_functionPackage: function(/*String*/ type, /*Array*/ data, /*Object*/ evt){
		dojo.debug("_functionPackage() name: " + evt.name + " for: " + evt.type + " with: " + type);
		evt.pkg = '';

		var data = dojo.doc._cache['function_names'];
		for(var key in data){
			if(dojo.lang.inArray(data[key], evt.name)){
				evt.pkg = key;
				break;
			}
		}

		if(evt.callbacks && evt.callbacks.length){
			var callback = evt.callbacks.shift();
			callback.call(null, type, data[key], evt);
		}
	},

	_sort: function(a, b){
		if(a[0] < b[0]){
			return -1;
		}
		if(a[0] > b[0]){
			return 1;
		}
	  return 0;
	}
});

dojo.event.topic.subscribe("/doc/search", dojo.doc, "_onDocSearch");
dojo.event.topic.subscribe("/doc/selectFunction", dojo.doc, "_onDocSelectFunction");

dojo.event.topic.registerPublisher("/doc/results", dojo.doc, "_printResults");
dojo.event.topic.registerPublisher("/doc/functionDetail", dojo.doc, "_printFunctionDetail");