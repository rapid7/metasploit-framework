/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.Deferred");
dojo.require("dojo.lang.func");

dojo.Deferred = function(/* optional */ canceller){
	/*
	NOTE: this namespace and documentation are imported wholesale 
		from MochiKit

	Encapsulates a sequence of callbacks in response to a value that
	may not yet be available.  This is modeled after the Deferred class
	from Twisted <http://twistedmatrix.com>.

	Why do we want this?  JavaScript has no threads, and even if it did,
	threads are hard.  Deferreds are a way of abstracting non-blocking
	events, such as the final response to an XMLHttpRequest.

	The sequence of callbacks is internally represented as a list
	of 2-tuples containing the callback/errback pair.  For example,
	the following call sequence::

		var d = new Deferred();
		d.addCallback(myCallback);
		d.addErrback(myErrback);
		d.addBoth(myBoth);
		d.addCallbacks(myCallback, myErrback);

	is translated into a Deferred with the following internal
	representation::

		[
			[myCallback, null],
			[null, myErrback],
			[myBoth, myBoth],
			[myCallback, myErrback]
		]

	The Deferred also keeps track of its current status (fired).
	Its status may be one of three things:

		-1: no value yet (initial condition)
		0: success
		1: error

	A Deferred will be in the error state if one of the following
	three conditions are met:

		1. The result given to callback or errback is "instanceof" Error
		2. The previous callback or errback raised an exception while
		   executing
		3. The previous callback or errback returned a value "instanceof"
			Error

	Otherwise, the Deferred will be in the success state.  The state of
	the Deferred determines the next element in the callback sequence to
	run.

	When a callback or errback occurs with the example deferred chain,
	something equivalent to the following will happen (imagine that
	exceptions are caught and returned)::

		// d.callback(result) or d.errback(result)
		if(!(result instanceof Error)){
			result = myCallback(result);
		}
		if(result instanceof Error){
			result = myErrback(result);
		}
		result = myBoth(result);
		if(result instanceof Error){
			result = myErrback(result);
		}else{
			result = myCallback(result);
		}

	The result is then stored away in case another step is added to the
	callback sequence.	Since the Deferred already has a value available,
	any new callbacks added will be called immediately.

	There are two other "advanced" details about this implementation that
	are useful:

	Callbacks are allowed to return Deferred instances themselves, so you
	can build complicated sequences of events with ease.

	The creator of the Deferred may specify a canceller.  The canceller
	is a function that will be called if Deferred.cancel is called before
	the Deferred fires.	 You can use this to implement clean aborting of
	an XMLHttpRequest, etc.	 Note that cancel will fire the deferred with
	a CancelledError (unless your canceller returns another kind of
	error), so the errbacks should be prepared to handle that error for
	cancellable Deferreds.

	*/
	
	this.chain = [];
	this.id = this._nextId();
	this.fired = -1;
	this.paused = 0;
	this.results = [null, null];
	this.canceller = canceller;
	this.silentlyCancelled = false;
};

dojo.lang.extend(dojo.Deferred, {
	getFunctionFromArgs: function(){
		var a = arguments;
		if((a[0])&&(!a[1])){
			if(dojo.lang.isFunction(a[0])){
				return a[0];
			}else if(dojo.lang.isString(a[0])){
				return dj_global[a[0]];
			}
		}else if((a[0])&&(a[1])){
			return dojo.lang.hitch(a[0], a[1]);
		}
		return null;
	},

	repr: function(){
		var state;
		if(this.fired == -1){
			state = 'unfired';
		}else if(this.fired == 0){
			state = 'success';
		} else {
			state = 'error';
		}
		return 'Deferred(' + this.id + ', ' + state + ')';
	},

	toString: dojo.lang.forward("repr"),

	_nextId: (function(){
		var n = 1;
		return function(){ return n++; };
	})(),

	cancel: function(){
		/***
		Cancels a Deferred that has not yet received a value, or is
		waiting on another Deferred as its value.

		If a canceller is defined, the canceller is called. If the
		canceller did not return an error, or there was no canceller,
		then the errback chain is started with CancelledError.
		***/
		if(this.fired == -1){
			if (this.canceller){
				this.canceller(this);
			}else{
				this.silentlyCancelled = true;
			}
			if(this.fired == -1){
				this.errback(new Error(this.repr()));
			}
		}else if(	(this.fired == 0)&&
					(this.results[0] instanceof dojo.Deferred)){
			this.results[0].cancel();
		}
	},
			

	_pause: function(){
		// Used internally to signal that it's waiting on another Deferred
		this.paused++;
	},

	_unpause: function(){
		// Used internally to signal that it's no longer waiting on
		// another Deferred.
		this.paused--;
		if ((this.paused == 0) && (this.fired >= 0)) {
			this._fire();
		}
	},

	_continue: function(res){
		// Used internally when a dependent deferred fires.
		this._resback(res);
		this._unpause();
	},

	_resback: function(res){
		// The primitive that means either callback or errback
		this.fired = ((res instanceof Error) ? 1 : 0);
		this.results[this.fired] = res;
		this._fire();
	},

	_check: function(){
		if(this.fired != -1){
			if(!this.silentlyCancelled){
				dojo.raise("already called!");
			}
			this.silentlyCancelled = false;
			return;
		}
	},

	callback: function(res){
		/*
		Begin the callback sequence with a non-error value.
		
		callback or errback should only be called once on a given
		Deferred.
		*/
		this._check();
		this._resback(res);
	},

	errback: function(res){
		// Begin the callback sequence with an error result.
		this._check();
		if(!(res instanceof Error)){
			res = new Error(res);
		}
		this._resback(res);
	},

	addBoth: function(cb, cbfn){
		/*
		Add the same function as both a callback and an errback as the
		next element on the callback sequence.	This is useful for code
		that you want to guarantee to run, e.g. a finalizer.
		*/
		var enclosed = this.getFunctionFromArgs(cb, cbfn);
		if(arguments.length > 2){
			enclosed = dojo.lang.curryArguments(null, enclosed, arguments, 2);
		}
		return this.addCallbacks(enclosed, enclosed);
	},

	addCallback: function(cb, cbfn){
		// Add a single callback to the end of the callback sequence.
		var enclosed = this.getFunctionFromArgs(cb, cbfn);
		if(arguments.length > 2){
			enclosed = dojo.lang.curryArguments(null, enclosed, arguments, 2);
		}
		return this.addCallbacks(enclosed, null);
	},

	addErrback: function(cb, cbfn){
		// Add a single callback to the end of the callback sequence.
		var enclosed = this.getFunctionFromArgs(cb, cbfn);
		if(arguments.length > 2){
			enclosed = dojo.lang.curryArguments(null, enclosed, arguments, 2);
		}
		return this.addCallbacks(null, enclosed);
		return this.addCallbacks(null, cbfn);
	},

	addCallbacks: function (cb, eb) {
		// Add separate callback and errback to the end of the callback
		// sequence.
		this.chain.push([cb, eb])
		if (this.fired >= 0) {
			this._fire();
		}
		return this;
	},

	_fire: function(){
		// Used internally to exhaust the callback sequence when a result
		// is available.
		var chain = this.chain;
		var fired = this.fired;
		var res = this.results[fired];
		var self = this;
		var cb = null;
		while (chain.length > 0 && this.paused == 0) {
			// Array
			var pair = chain.shift();
			var f = pair[fired];
			if (f == null) {
				continue;
			}
			try {
				res = f(res);
				fired = ((res instanceof Error) ? 1 : 0);
				if(res instanceof dojo.Deferred) {
					cb = function(res){
						self._continue(res);
					}
					this._pause();
				}
			}catch(err){
				fired = 1;
				res = err;
			}
		}
		this.fired = fired;
		this.results[fired] = res;
		if((cb)&&(this.paused)){
			// this is for "tail recursion" in case the dependent
			// deferred is already fired
			res.addBoth(cb);
		}
	}
});
