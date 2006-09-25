/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.graphics.color.hsl");
dojo.require("dojo.lang.array");

dojo.lang.extend(dojo.graphics.color.Color, {

	toHsl: function() {
		return dojo.graphics.color.rgb2hsl(this.toRgb());
	}
});

dojo.graphics.color.rgb2hsl = function(r, g, b){

	if (dojo.lang.isArray(r)) {
		b = r[2] || 0;
		g = r[1] || 0;
		r = r[0] || 0;
	}

	r /= 255;
	g /= 255;
	b /= 255;

	//
	// based on C code from http://astronomy.swin.edu.au/~pbourke/colour/hsl/
	//

	var h = null;
	var s = null;
	var l = null;


	var min = Math.min(r, g, b);
	var max = Math.max(r, g, b);
	var delta = max - min;

	l = (min + max) / 2;

	s = 0;

	if ((l > 0) && (l < 1)){
		s = delta / ((l < 0.5) ? (2 * l) : (2 - 2 * l));
	}

	h = 0;

	if (delta > 0) {
		if ((max == r) && (max != g)){
			h += (g - b) / delta;
		}
		if ((max == g) && (max != b)){
			h += (2 + (b - r) / delta);
		}
		if ((max == b) && (max != r)){
			h += (4 + (r - g) / delta);
		}
		h *= 60;
	}

	h = (h == 0) ? 360 : Math.ceil((h / 360) * 255);
	s = Math.ceil(s * 255);
	l = Math.ceil(l * 255);

	return [h, s, l];
}

dojo.graphics.color.hsl2rgb = function(h, s, l){
 
	if (dojo.lang.isArray(h)) {
		l = h[2] || 0;
		s = h[1] || 0;
		h = h[0] || 0;
	}

	h = (h / 255) * 360;
	if (h == 360){ h = 0;}
	s = s / 255;
	l = l / 255;

	//
	// based on C code from http://astronomy.swin.edu.au/~pbourke/colour/hsl/
	//


	while (h < 0){ h += 360; }
	while (h > 360){ h -= 360; }
	var r, g, b;
	if (h < 120){
		r = (120 - h) / 60;
		g = h / 60;
		b = 0;
	}else if (h < 240){
		r = 0;
		g = (240 - h) / 60;
		b = (h - 120) / 60;
	}else{
		r = (h - 240) / 60;
		g = 0;
		b = (360 - h) / 60;
	}

	r = Math.min(r, 1);
	g = Math.min(g, 1);
	b = Math.min(b, 1);

	r = 2 * s * r + (1 - s);
	g = 2 * s * g + (1 - s);
	b = 2 * s * b + (1 - s);

	if (l < 0.5){
		r = l * r;
		g = l * g;
		b = l * b;
	}else{
		r = (1 - l) * r + 2 * l - 1;
		g = (1 - l) * g + 2 * l - 1;
		b = (1 - l) * b + 2 * l - 1;
	}

	r = Math.ceil(r * 255);
	g = Math.ceil(g * 255);
	b = Math.ceil(b * 255);

	return [r, g, b];
}

dojo.graphics.color.hsl2hex = function(h, s, l){
	var rgb = dojo.graphics.color.hsl2rgb(h, s, l);
	return dojo.graphics.color.rgb2hex(rgb[0], rgb[1], rgb[2]);
}

dojo.graphics.color.hex2hsl = function(hex){
	var rgb = dojo.graphics.color.hex2rgb(hex);
	return dojo.graphics.color.rgb2hsl(rgb[0], rgb[1], rgb[2]);
}
