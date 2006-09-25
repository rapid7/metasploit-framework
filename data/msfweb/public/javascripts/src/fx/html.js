/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.fx.html");

dojo.require("dojo.style");
dojo.require("dojo.math.curves");
dojo.require("dojo.lang.func");
dojo.require("dojo.animation");
dojo.require("dojo.event.*");
dojo.require("dojo.graphics.color");

dojo.deprecated("dojo.fx.html", "use dojo.lfx.html instead", "0.4");

dojo.fx.duration = 300;

dojo.fx.html._makeFadeable = function(node){
	if(dojo.render.html.ie){
		// only set the zoom if the "tickle" value would be the same as the
		// default
		if( (node.style.zoom.length == 0) &&
			(dojo.style.getStyle(node, "zoom") == "normal") ){
			// make sure the node "hasLayout"
			// NOTE: this has been tested with larger and smaller user-set text
			// sizes and works fine
			node.style.zoom = "1";
			// node.style.zoom = "normal";
		}
		// don't set the width to auto if it didn't already cascade that way.
		// We don't want to f anyones designs
		if(	(node.style.width.length == 0) &&
			(dojo.style.getStyle(node, "width") == "auto") ){
			node.style.width = "auto";
		}
	}
}

dojo.fx.html.fadeOut = function(node, duration, callback, dontPlay) {
	return dojo.fx.html.fade(node, duration, dojo.style.getOpacity(node), 0, callback, dontPlay);
};

dojo.fx.html.fadeIn = function(node, duration, callback, dontPlay) {
	return dojo.fx.html.fade(node, duration, dojo.style.getOpacity(node), 1, callback, dontPlay);
};

dojo.fx.html.fadeHide = function(node, duration, callback, dontPlay) {
	node = dojo.byId(node);
	if(!duration) { duration = 150; } // why not have a default?
	return dojo.fx.html.fadeOut(node, duration, function(node) {
		node.style.display = "none";
		if(typeof callback == "function") { callback(node); }
	});
};

dojo.fx.html.fadeShow = function(node, duration, callback, dontPlay) {
	node = dojo.byId(node);
	if(!duration) { duration = 150; } // why not have a default?
	node.style.display = "block";
	return dojo.fx.html.fade(node, duration, 0, 1, callback, dontPlay);
};

dojo.fx.html.fade = function(node, duration, startOpac, endOpac, callback, dontPlay) {
	node = dojo.byId(node);
	dojo.fx.html._makeFadeable(node);
	var anim = new dojo.animation.Animation(
		new dojo.math.curves.Line([startOpac],[endOpac]),
		duration||dojo.fx.duration, 0);
	dojo.event.connect(anim, "onAnimate", function(e) {
		dojo.style.setOpacity(node, e.x);
	});
	if(callback) {
		dojo.event.connect(anim, "onEnd", function(e) {
			callback(node, anim);
		});
	}
	if(!dontPlay) { anim.play(true); }
	return anim;
};

dojo.fx.html.slideTo = function(node, duration, endCoords, callback, dontPlay) {
	if(!dojo.lang.isNumber(duration)) {
		var tmp = duration;
		duration = endCoords;
		endCoords = tmp;
	}
	node = dojo.byId(node);

	var top = node.offsetTop;
	var left = node.offsetLeft;
	var pos = dojo.style.getComputedStyle(node, 'position');

	if (pos == 'relative' || pos == 'static') {
		top = parseInt(dojo.style.getComputedStyle(node, 'top')) || 0;
		left = parseInt(dojo.style.getComputedStyle(node, 'left')) || 0;
	}

	return dojo.fx.html.slide(node, duration, [left, top],
		endCoords, callback, dontPlay);
};

dojo.fx.html.slideBy = function(node, duration, coords, callback, dontPlay) {
	if(!dojo.lang.isNumber(duration)) {
		var tmp = duration;
		duration = coords;
		coords = tmp;
	}
	node = dojo.byId(node);

	var top = node.offsetTop;
	var left = node.offsetLeft;
	var pos = dojo.style.getComputedStyle(node, 'position');

	if (pos == 'relative' || pos == 'static') {
		top = parseInt(dojo.style.getComputedStyle(node, 'top')) || 0;
		left = parseInt(dojo.style.getComputedStyle(node, 'left')) || 0;
	}

	return dojo.fx.html.slideTo(node, duration, [left+coords[0], top+coords[1]],
		callback, dontPlay);
};

dojo.fx.html.slide = function(node, duration, startCoords, endCoords, callback, dontPlay) {
	if(!dojo.lang.isNumber(duration)) {
		var tmp = duration;
		duration = endCoords;
		endCoords = startCoords;
		startCoords = tmp;
	}
	node = dojo.byId(node);

	if (dojo.style.getComputedStyle(node, 'position') == 'static') {
		node.style.position = 'relative';
	}

	var anim = new dojo.animation.Animation(
		new dojo.math.curves.Line(startCoords, endCoords),
		duration||dojo.fx.duration, 0);
	dojo.event.connect(anim, "onAnimate", function(e) {
		with( node.style ) {
			left = e.x + "px";
			top = e.y + "px";
		}
	});
	if(callback) {
		dojo.event.connect(anim, "onEnd", function(e) {
			callback(node, anim);
		});
	}
	if(!dontPlay) { anim.play(true); }
	return anim;
};

// Fade from startColor to the node's background color
dojo.fx.html.colorFadeIn = function(node, duration, startColor, delay, callback, dontPlay) {
	if(!dojo.lang.isNumber(duration)) {
		var tmp = duration;
		duration = startColor;
		startColor = tmp;
	}
	node = dojo.byId(node);
	var color = dojo.style.getBackgroundColor(node);
	var bg = dojo.style.getStyle(node, "background-color").toLowerCase();
	var wasTransparent = bg == "transparent" || bg == "rgba(0, 0, 0, 0)";
	while(color.length > 3) { color.pop(); }

	var rgb = new dojo.graphics.color.Color(startColor).toRgb();
	var anim = dojo.fx.html.colorFade(node, duration||dojo.fx.duration, startColor, color, callback, true);
	dojo.event.connect(anim, "onEnd", function(e) {
		if( wasTransparent ) {
			node.style.backgroundColor = "transparent";
		}
	});
	if( delay > 0 ) {
		node.style.backgroundColor = "rgb(" + rgb.join(",") + ")";
		if(!dontPlay) { setTimeout(function(){anim.play(true)}, delay); }
	} else {
		if(!dontPlay) { anim.play(true); }
	}
	return anim;
};
// alias for (probably?) common use/terminology
dojo.fx.html.highlight = dojo.fx.html.colorFadeIn;
dojo.fx.html.colorFadeFrom = dojo.fx.html.colorFadeIn;

// Fade from node's background color to endColor
dojo.fx.html.colorFadeOut = function(node, duration, endColor, delay, callback, dontPlay) {
	if(!dojo.lang.isNumber(duration)) {
		var tmp = duration;
		duration = endColor;
		endColor = tmp;
	}
	node = dojo.byId(node);
	var color = new dojo.graphics.color.Color(dojo.style.getBackgroundColor(node)).toRgb();

	var rgb = new dojo.graphics.color.Color(endColor).toRgb();
	var anim = dojo.fx.html.colorFade(node, duration||dojo.fx.duration, color, rgb, callback, delay > 0 || dontPlay);
	if( delay > 0 ) {
		node.style.backgroundColor = "rgb(" + color.join(",") + ")";
		if(!dontPlay) { setTimeout(function(){anim.play(true)}, delay); }
	}
	return anim;
};
// FIXME: not sure which name is better. an alias here may be bad.
dojo.fx.html.unhighlight = dojo.fx.html.colorFadeOut;
dojo.fx.html.colorFadeTo = dojo.fx.html.colorFadeOut;

// Fade node background from startColor to endColor
dojo.fx.html.colorFade = function(node, duration, startColor, endColor, callback, dontPlay) {
	if(!dojo.lang.isNumber(duration)) {
		var tmp = duration;
		duration = endColor;
		endColor = startColor;
		startColor = tmp;
	}
	node = dojo.byId(node);
	var startRgb = new dojo.graphics.color.Color(startColor).toRgb();
	var endRgb = new dojo.graphics.color.Color(endColor).toRgb();
	var anim = new dojo.animation.Animation(
		new dojo.math.curves.Line(startRgb, endRgb),
		duration||dojo.fx.duration, 0);
	dojo.event.connect(anim, "onAnimate", function(e) {
		node.style.backgroundColor = "rgb(" + e.coordsAsInts().join(",") + ")";
	});
	if(callback) {
		dojo.event.connect(anim, "onEnd", function(e) {
			callback(node, anim);
		});
	}
	if( !dontPlay ) { anim.play(true); }
	return anim;
};

dojo.fx.html.wipeIn = function(node, duration, callback, dontPlay) {
	node = dojo.byId(node);
	var overflow = dojo.style.getStyle(node, "overflow");
	if(overflow == "visible") {
		node.style.overflow = "hidden";
	}
	node.style.height = 0;
	dojo.style.show(node);
	var anim = dojo.fx.html.wipe(node, duration, 0, node.scrollHeight, null, true);
	dojo.event.connect(anim, "onEnd", function() {
		node.style.overflow = overflow;
		node.style.visibility = "";
		node.style.height = "auto";
		if(callback) { callback(node, anim); }
	});
	if(!dontPlay) { anim.play(); }
	return anim;
}

dojo.fx.html.wipeOut = function(node, duration, callback, dontPlay) {
	node = dojo.byId(node);
	var overflow = dojo.style.getStyle(node, "overflow");
	if(overflow == "visible") {
		node.style.overflow = "hidden";
	}
	var anim = dojo.fx.html.wipe(node, duration, node.offsetHeight, 0, null, true);
	dojo.event.connect(anim, "onEnd", function() {
		dojo.style.hide(node);
		node.style.visibility = "hidden";
		node.style.overflow = overflow;
		if(callback) { callback(node, anim); }
	});
	if(!dontPlay) { anim.play(); }
	return anim;
}

dojo.fx.html.wipe = function(node, duration, startHeight, endHeight, callback, dontPlay) {
	node = dojo.byId(node);
	var anim = new dojo.animation.Animation([[startHeight], [endHeight]], duration||dojo.fx.duration, 0);
	dojo.event.connect(anim, "onAnimate", function(e) {
		node.style.height = e.x + "px";
	});
	dojo.event.connect(anim, "onEnd", function() {
		if(callback) { callback(node, anim); }
	});
	if(!dontPlay) { anim.play(); }
	return anim;
}

dojo.fx.html.wiper = function(node, controlNode) {
	this.node = dojo.byId(node);
	if(controlNode) {
		dojo.event.connect(dojo.byId(controlNode), "onclick", this, "toggle");
	}
}
dojo.lang.extend(dojo.fx.html.wiper, {
	duration: dojo.fx.duration,
	_anim: null,

	toggle: function() {
		if(!this._anim) {
			var type = "wipe" + (dojo.style.isVisible(this.node) ? "Out" : "In");
			this._anim = dojo.fx[type](this.node, this.duration, dojo.lang.hitch(this, "_callback"));
		}
	},

	_callback: function() {
		this._anim = null;
	}
});

dojo.fx.html.explode = function(start, endNode, duration, callback, dontPlay) {
	var startCoords = dojo.style.toCoordinateArray(start);

	var outline = document.createElement("div");
	with(outline.style) {
		position = "absolute";
		border = "1px solid black";
		display = "none";
	}
	document.body.appendChild(outline);

	endNode = dojo.byId(endNode);
	with(endNode.style) {
		visibility = "hidden";
		display = "block";
	}
	var endCoords = dojo.style.toCoordinateArray(endNode);

	with(endNode.style) {
		display = "none";
		visibility = "visible";
	}

	var anim = new dojo.animation.Animation(
		new dojo.math.curves.Line(startCoords, endCoords),
		duration||dojo.fx.duration, 0
	);
	dojo.event.connect(anim, "onBegin", function(e) {
		outline.style.display = "block";
	});
	dojo.event.connect(anim, "onAnimate", function(e) {
		with(outline.style) {
			left = e.x + "px";
			top = e.y + "px";
			width = e.coords[2] + "px";
			height = e.coords[3] + "px";
		}
	});

	dojo.event.connect(anim, "onEnd", function() {
		endNode.style.display = "block";
		outline.parentNode.removeChild(outline);
		if(callback) { callback(endNode, anim); }
	});
	if(!dontPlay) { anim.play(); }
	return anim;
};

dojo.fx.html.implode = function(startNode, end, duration, callback, dontPlay) {
	var startCoords = dojo.style.toCoordinateArray(startNode);
	var endCoords = dojo.style.toCoordinateArray(end);

	startNode = dojo.byId(startNode);
	var outline = document.createElement("div");
	with(outline.style) {
		position = "absolute";
		border = "1px solid black";
		display = "none";
	}
	document.body.appendChild(outline);

	var anim = new dojo.animation.Animation(
		new dojo.math.curves.Line(startCoords, endCoords),
		duration||dojo.fx.duration, 0
	);
	dojo.event.connect(anim, "onBegin", function(e) {
		startNode.style.display = "none";
		outline.style.display = "block";
	});
	dojo.event.connect(anim, "onAnimate", function(e) {
		with(outline.style) {
			left = e.x + "px";
			top = e.y + "px";
			width = e.coords[2] + "px";
			height = e.coords[3] + "px";
		}
	});

	dojo.event.connect(anim, "onEnd", function() {
		outline.parentNode.removeChild(outline);
		if(callback) { callback(startNode, anim); }
	});
	if(!dontPlay) { anim.play(); }
	return anim;
};

dojo.fx.html.Exploder = function(triggerNode, boxNode) {
	triggerNode = dojo.byId(triggerNode);
	boxNode = dojo.byId(boxNode);
	var _this = this;

	// custom options
	this.waitToHide = 500;
	this.timeToShow = 100;
	this.waitToShow = 200;
	this.timeToHide = 70;
	this.autoShow = false;
	this.autoHide = false;

	var animShow = null;
	var animHide = null;

	var showTimer = null;
	var hideTimer = null;

	var startCoords = null;
	var endCoords = null;

	this.showing = false;

	this.onBeforeExplode = null;
	this.onAfterExplode = null;
	this.onBeforeImplode = null;
	this.onAfterImplode = null;
	this.onExploding = null;
	this.onImploding = null;

	this.timeShow = function() {
		clearTimeout(showTimer);
		showTimer = setTimeout(_this.show, _this.waitToShow);
	}

	this.show = function() {
		clearTimeout(showTimer);
		clearTimeout(hideTimer);
		//triggerNode.blur();

		if( (animHide && animHide.status() == "playing")
			|| (animShow && animShow.status() == "playing")
			|| _this.showing ) { return; }

		if(typeof _this.onBeforeExplode == "function") { _this.onBeforeExplode(triggerNode, boxNode); }
		animShow = dojo.fx.html.explode(triggerNode, boxNode, _this.timeToShow, function(e) {
			_this.showing = true;
			if(typeof _this.onAfterExplode == "function") { _this.onAfterExplode(triggerNode, boxNode); }
		});
		if(typeof _this.onExploding == "function") {
			dojo.event.connect(animShow, "onAnimate", this, "onExploding");
		}
	}

	this.timeHide = function() {
		clearTimeout(showTimer);
		clearTimeout(hideTimer);
		if(_this.showing) {
			hideTimer = setTimeout(_this.hide, _this.waitToHide);
		}
	}

	this.hide = function() {
		clearTimeout(showTimer);
		clearTimeout(hideTimer);
		if( animShow && animShow.status() == "playing" ) {
			return;
		}

		_this.showing = false;
		if(typeof _this.onBeforeImplode == "function") { _this.onBeforeImplode(triggerNode, boxNode); }
		animHide = dojo.fx.html.implode(boxNode, triggerNode, _this.timeToHide, function(e){
			if(typeof _this.onAfterImplode == "function") { _this.onAfterImplode(triggerNode, boxNode); }
		});
		if(typeof _this.onImploding == "function") {
			dojo.event.connect(animHide, "onAnimate", this, "onImploding");
		}
	}

	// trigger events
	dojo.event.connect(triggerNode, "onclick", function(e) {
		if(_this.showing) {
			_this.hide();
		} else {
			_this.show();
		}
	});
	dojo.event.connect(triggerNode, "onmouseover", function(e) {
		if(_this.autoShow) {
			_this.timeShow();
		}
	});
	dojo.event.connect(triggerNode, "onmouseout", function(e) {
		if(_this.autoHide) {
			_this.timeHide();
		}
	});

	// box events
	dojo.event.connect(boxNode, "onmouseover", function(e) {
		clearTimeout(hideTimer);
	});
	dojo.event.connect(boxNode, "onmouseout", function(e) {
		if(_this.autoHide) {
			_this.timeHide();
		}
	});

	// document events
	dojo.event.connect(document.documentElement || document.body, "onclick", function(e) {
		function isDesc(node, ancestor) {
			while(node) {
				if(node == ancestor){ return true; }
				node = node.parentNode;
			}
			return false;
		}
		if(_this.autoHide && _this.showing
			&& !isDesc(e.target, boxNode)
			&& !isDesc(e.target, triggerNode) ) {
			_this.hide();
		}
	});

	return this;
};

/**** 
	Strategies for displaying/hiding objects
	This presents a standard interface for each of the effects
*****/
dojo.fx.html.toggle={}

dojo.fx.html.toggle.plain = {
	show: function(node, duration, explodeSrc, callback){
		dojo.style.show(node);
		if(dojo.lang.isFunction(callback)){ callback(); }
	},

	hide: function(node, duration, explodeSrc, callback){
		dojo.style.hide(node);
		if(dojo.lang.isFunction(callback)){ callback(); }
	}
}

dojo.fx.html.toggle.fade = {
	show: function(node, duration, explodeSrc, callback){
		dojo.fx.html.fadeShow(node, duration, callback);
	},

	hide: function(node, duration, explodeSrc, callback){
		dojo.fx.html.fadeHide(node, duration, callback);
	}
}

dojo.fx.html.toggle.wipe = {
	show: function(node, duration, explodeSrc, callback){
		dojo.fx.html.wipeIn(node, duration, callback);
	},

	hide: function(node, duration, explodeSrc, callback){
		dojo.fx.html.wipeOut(node, duration, callback);
	}
}

dojo.fx.html.toggle.explode = {
	show: function(node, duration, explodeSrc, callback){
		dojo.fx.html.explode(explodeSrc||[0,0,0,0], node, duration, callback);
	},

	hide: function(node, duration, explodeSrc, callback){
		dojo.fx.html.implode(node, explodeSrc||[0,0,0,0], duration, callback);
	}
}

dojo.lang.mixin(dojo.fx, dojo.fx.html);
