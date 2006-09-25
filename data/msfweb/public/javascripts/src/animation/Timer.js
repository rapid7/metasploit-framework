/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.animation.Timer");
dojo.require("dojo.lang.func");

dojo.animation.Timer = function(intvl){
	var timer = null;
	this.isRunning = false;
	this.interval = intvl;

	this.onTick = function(){};
	this.onStart = null;
	this.onStop = null;

	this.setInterval = function(ms){
		if (this.isRunning) window.clearInterval(timer);
		this.interval = ms;
		if (this.isRunning) timer = window.setInterval(dojo.lang.hitch(this, "onTick"), this.interval);
	};

	this.start = function(){
		if (typeof this.onStart == "function") this.onStart();
		this.isRunning = true;
		timer = window.setInterval(this.onTick, this.interval);
	};
	this.stop = function(){
		if (typeof this.onStop == "function") this.onStop();
		this.isRunning = false;
		window.clearInterval(timer);
	};
};
