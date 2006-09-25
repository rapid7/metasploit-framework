/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/*		This is the dojo logging facility, which is imported from nWidgets
		(written by Alex Russell, CLA on file), which is patterned on the
		Python logging module, which in turn has been heavily influenced by
		log4j (execpt with some more pythonic choices, which we adopt as well).

		While the dojo logging facilities do provide a set of familiar
		interfaces, many of the details are changed to reflect the constraints
		of the browser environment. Mainly, file and syslog-style logging
		facilites are not provided, with HTTP POST and GET requests being the
		only ways of getting data from the browser back to a server. Minimal
		support for this (and XML serialization of logs) is provided, but may
		not be of practical use in a deployment environment.

		The Dojo logging classes are agnostic of any environment, and while
		default loggers are provided for browser-based interpreter
		environments, this file and the classes it define are explicitly
		designed to be portable to command-line interpreters and other
		ECMA-262v3 envrionments.

	the logger needs to accomidate:
		log "levels"
		type identifiers
		file?
		message
		tic/toc?

	The logger should ALWAYS record:
		time/date logged
		message
		type
		level
*/
// TODO: conver documentation to javadoc style once we confirm that is our choice
// TODO: define DTD for XML-formatted log messages
// TODO: write XML Formatter class
// TODO: write HTTP Handler which uses POST to send log lines/sections

// Filename:	LogCore.js
// Purpose:		a common logging infrastructure for dojo
// Classes:		dojo.logging, dojo.logging.Logger, dojo.logging.Record, dojo.logging.LogFilter
// Global Objects:	dojo.logging
// Dependencies:	none

dojo.provide("dojo.logging.Logger");
dojo.provide("dojo.log");
dojo.require("dojo.lang");

/*
	A simple data structure class that stores information for and about
	a logged event. Objects of this type are created automatically when
	an event is logged and are the internal format in which information
	about log events is kept.
*/

dojo.logging.Record = function(lvl, msg){
	this.level = lvl;
	this.message = msg;
	this.time = new Date();
	// FIXME: what other information can we receive/discover here?
}

// an empty parent (abstract) class which concrete filters should inherit from.
dojo.logging.LogFilter = function(loggerChain){
	this.passChain = loggerChain || "";
	this.filter = function(record){
		// FIXME: need to figure out a way to enforce the loggerChain
		// restriction
		return true; // pass all records
	}
}

dojo.logging.Logger = function(){
	this.cutOffLevel = 0;
	this.propagate = true;
	this.parent = null;
	// storage for dojo.logging.Record objects seen and accepted by this logger
	this.data = [];
	this.filters = [];
	this.handlers = [];
}

dojo.lang.extend(dojo.logging.Logger, {
	argsToArr: function(args){
		// utility function, reproduced from __util__ here to remove dependency
		var ret = [];
		for(var x=0; x<args.length; x++){
			ret.push(args[x]);
		}
		return ret;
	},

	setLevel: function(lvl){
		this.cutOffLevel = parseInt(lvl);
	},

	isEnabledFor: function(lvl){
		return parseInt(lvl) >= this.cutOffLevel;
	},

	getEffectiveLevel: function(){
		if((this.cutOffLevel==0)&&(this.parent)){
			return this.parent.getEffectiveLevel();
		}
		return this.cutOffLevel;
	},

	addFilter: function(flt){
		this.filters.push(flt);
		return this.filters.length-1;
	},

	removeFilterByIndex: function(fltIndex){
		if(this.filters[fltIndex]){
			delete this.filters[fltIndex];
			return true;
		}
		return false;
	},

	removeFilter: function(fltRef){
		for(var x=0; x<this.filters.length; x++){
			if(this.filters[x]===fltRef){
				delete this.filters[x];
				return true;
			}
		}
		return false;
	},

	removeAllFilters: function(){
		this.filters = []; // clobber all of them
	},

	filter: function(rec){
		for(var x=0; x<this.filters.length; x++){
			if((this.filters[x]["filter"])&&
			   (!this.filters[x].filter(rec))||
			   (rec.level<this.cutOffLevel)){
				return false;
			}
		}
		return true;
	},

	addHandler: function(hdlr){
		this.handlers.push(hdlr);
		return this.handlers.length-1;
	},

	handle: function(rec){
		if((!this.filter(rec))||(rec.level<this.cutOffLevel)){ return false; }
		for(var x=0; x<this.handlers.length; x++){
			if(this.handlers[x]["handle"]){
			   this.handlers[x].handle(rec);
			}
		}
		// FIXME: not sure what to do about records to be propagated that may have
		// been modified by the handlers or the filters at this logger. Should
		// parents always have pristine copies? or is passing the modified record
		// OK?
		// if((this.propagate)&&(this.parent)){ this.parent.handle(rec); }
		return true;
	},

	// the heart and soul of the logging system
	log: function(lvl, msg){
		if(	(this.propagate)&&(this.parent)&&
			(this.parent.rec.level>=this.cutOffLevel)){
			this.parent.log(lvl, msg);
			return false;
		}
		// FIXME: need to call logging providers here!
		this.handle(new dojo.logging.Record(lvl, msg));
		return true;
	},

	// logger helpers
	debug:function(msg){
		return this.logType("DEBUG", this.argsToArr(arguments));
	},

	info: function(msg){
		return this.logType("INFO", this.argsToArr(arguments));
	},

	warning: function(msg){
		return this.logType("WARNING", this.argsToArr(arguments));
	},

	error: function(msg){
		return this.logType("ERROR", this.argsToArr(arguments));
	},

	critical: function(msg){
		return this.logType("CRITICAL", this.argsToArr(arguments));
	},

	exception: function(msg, e, squelch){
		// FIXME: this needs to be modified to put the exception in the msg
		// if we're on Moz, we can get the following from the exception object:
		//		lineNumber
		//		message
		//		fileName
		//		stack
		//		name
		// on IE, we get:
		//		name
		//		message (from MDA?)
		//		number
		//		description (same as message!)
		if(e){
			var eparts = [e.name, (e.description||e.message)];
			if(e.fileName){
				eparts.push(e.fileName);
				eparts.push("line "+e.lineNumber);
				// eparts.push(e.stack);
			}
			msg += " "+eparts.join(" : ");
		}

		this.logType("ERROR", msg);
		if(!squelch){
			throw e;
		}
	},

	logType: function(type, args){
		var na = [dojo.logging.log.getLevel(type)];
		if(typeof args == "array"){
			na = na.concat(args);
		}else if((typeof args == "object")&&(args["length"])){
			na = na.concat(this.argsToArr(args));
			/* for(var x=0; x<args.length; x++){
				na.push(args[x]);
			} */
		}else{
			na = na.concat(this.argsToArr(arguments).slice(1));
			/* for(var x=1; x<arguments.length; x++){
				na.push(arguments[x]);
			} */
		}
		return this.log.apply(this, na);
	}
});

void(function(){
	var ptype = dojo.logging.Logger.prototype;
	ptype.warn = ptype.warning;
	ptype.err = ptype.error;
	ptype.crit = ptype.critical;
})();

// the Handler class
dojo.logging.LogHandler = function(level){
	this.cutOffLevel = (level) ? level : 0;
	this.formatter = null; // FIXME: default formatter?
	this.data = [];
	this.filters = [];
}

dojo.logging.LogHandler.prototype.setFormatter = function(fmtr){
	// FIXME: need to vet that it is indeed a formatter object
	dojo.unimplemented("setFormatter");
}

dojo.logging.LogHandler.prototype.flush = function(){
	dojo.unimplemented("flush");
}

dojo.logging.LogHandler.prototype.close = function(){
	dojo.unimplemented("close");
}

dojo.logging.LogHandler.prototype.handleError = function(){
	dojo.unimplemented("handleError");
}

dojo.logging.LogHandler.prototype.handle = function(record){
	// emits the passed record if it passes this object's filters
	if((this.filter(record))&&(record.level>=this.cutOffLevel)){
		this.emit(record);
	}
}

dojo.logging.LogHandler.prototype.emit = function(record){
	// do whatever is necessaray to actually log the record
	dojo.unimplemented("emit");
}

// set aliases since we don't want to inherit from dojo.logging.Logger
void(function(){ // begin globals protection closure
	var names = [
		"setLevel", "addFilter", "removeFilterByIndex", "removeFilter",
		"removeAllFilters", "filter"
	];
	var tgt = dojo.logging.LogHandler.prototype;
	var src = dojo.logging.Logger.prototype;
	for(var x=0; x<names.length; x++){
		tgt[names[x]] = src[names[x]];
	}
})(); // end globals protection closure

dojo.logging.log = new dojo.logging.Logger();

// an associative array of logger objects. This object inherits from
// a list of level names with their associated numeric levels
dojo.logging.log.levels = [ {"name": "DEBUG", "level": 1},
						   {"name": "INFO", "level": 2},
						   {"name": "WARNING", "level": 3},
						   {"name": "ERROR", "level": 4},
						   {"name": "CRITICAL", "level": 5} ];

dojo.logging.log.loggers = {};

dojo.logging.log.getLogger = function(name){
	if(!this.loggers[name]){
		this.loggers[name] = new dojo.logging.Logger();
		this.loggers[name].parent = this;
	}
	return this.loggers[name];
}

dojo.logging.log.getLevelName = function(lvl){
	for(var x=0; x<this.levels.length; x++){
		if(this.levels[x].level == lvl){
			return this.levels[x].name;
		}
	}
	return null;
}

dojo.logging.log.addLevelName = function(name, lvl){
	if(this.getLevelName(name)){
		this.err("could not add log level "+name+" because a level with that name already exists");
		return false;
	}
	this.levels.append({"name": name, "level": parseInt(lvl)});
	return true;
}

dojo.logging.log.getLevel = function(name){
	for(var x=0; x<this.levels.length; x++){
		if(this.levels[x].name.toUpperCase() == name.toUpperCase()){
			return this.levels[x].level;
		}
	}
	return null;
}

// a default handler class, it simply saves all of the handle()'d records in
// memory. Useful for attaching to with dojo.event.connect()
dojo.logging.MemoryLogHandler = function(level, recordsToKeep, postType, postInterval){
	// mixin style inheritance
	dojo.logging.LogHandler.call(this, level);
	// default is unlimited
	this.numRecords = (typeof djConfig['loggingNumRecords'] != 'undefined') ? djConfig['loggingNumRecords'] : ((recordsToKeep) ? recordsToKeep : -1);
	// 0=count, 1=time, -1=don't post TODO: move this to a better location for prefs
	this.postType = (typeof djConfig['loggingPostType'] != 'undefined') ? djConfig['loggingPostType'] : ( postType || -1);
	// milliseconds for time, interger for number of records, -1 for non-posting,
	this.postInterval = (typeof djConfig['loggingPostInterval'] != 'undefined') ? djConfig['loggingPostInterval'] : ( postType || -1);
	
}
// prototype inheritance
dojo.logging.MemoryLogHandler.prototype = new dojo.logging.LogHandler();

// FIXME
// dojo.inherits(dojo.logging.MemoryLogHandler, 

// over-ride base-class
dojo.logging.MemoryLogHandler.prototype.emit = function(record){
	this.data.push(record);
	if(this.numRecords != -1){
		while(this.data.length>this.numRecords){
			this.data.shift();
		}
	}
}

dojo.logging.logQueueHandler = new dojo.logging.MemoryLogHandler(0,50,0,10000);
// actual logging event handler
dojo.logging.logQueueHandler.emit = function(record){
	// we should probably abstract this in the future
	var logStr = String(dojo.log.getLevelName(record.level)+": "+record.time.toLocaleTimeString())+": "+record.message;
	if(!dj_undef("debug", dj_global)){
		dojo.debug(logStr);
	}else if((typeof dj_global["print"] == "function")&&(!dojo.render.html.capable)){
		print(logStr);
	}
	this.data.push(record);
	if(this.numRecords != -1){
		while(this.data.length>this.numRecords){
			this.data.shift();
		}
	}
}

dojo.logging.log.addHandler(dojo.logging.logQueueHandler);
dojo.log = dojo.logging.log;
