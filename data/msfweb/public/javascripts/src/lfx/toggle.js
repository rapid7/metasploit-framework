/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.lfx.toggle");
dojo.require("dojo.lfx.*");

dojo.lfx.toggle.plain = {
	show: function(node, duration, easing, callback){
		dojo.style.show(node);
		if(dojo.lang.isFunction(callback)){ callback(); }
	},
	
	hide: function(node, duration, easing, callback){
		dojo.style.hide(node);
		if(dojo.lang.isFunction(callback)){ callback(); }
	}
}

dojo.lfx.toggle.fade = {
	show: function(node, duration, easing, callback){
		dojo.lfx.fadeShow(node, duration, easing, callback).play();
	},

	hide: function(node, duration, easing, callback){
		dojo.lfx.fadeHide(node, duration, easing, callback).play();
	}
}

dojo.lfx.toggle.wipe = {
	show: function(node, duration, easing, callback){
		dojo.lfx.wipeIn(node, duration, easing, callback).play();
	},

	hide: function(node, duration, easing, callback){
		dojo.lfx.wipeOut(node, duration, easing, callback).play();
	}
}

dojo.lfx.toggle.explode = {
	show: function(node, duration, easing, callback, explodeSrc){
		dojo.lfx.explode(explodeSrc||[0,0,0,0], node, duration, easing, callback).play();
	},

	hide: function(node, duration, easing, callback, explodeSrc){
		dojo.lfx.implode(node, explodeSrc||[0,0,0,0], duration, easing, callback).play();
	}
}
