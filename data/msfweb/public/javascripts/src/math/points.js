/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.math.points");
dojo.require("dojo.math");

// TODO: add a Point class?
dojo.math.points = {
	translate: function(a, b) {
		if( a.length != b.length ) {
			dojo.raise("dojo.math.translate: points not same size (a:[" + a + "], b:[" + b + "])");
		}
		var c = new Array(a.length);
		for(var i = 0; i < a.length; i++) {
			c[i] = a[i] + b[i];
		}
		return c;
	},

	midpoint: function(a, b) {
		if( a.length != b.length ) {
			dojo.raise("dojo.math.midpoint: points not same size (a:[" + a + "], b:[" + b + "])");
		}
		var c = new Array(a.length);
		for(var i = 0; i < a.length; i++) {
			c[i] = (a[i] + b[i]) / 2;
		}
		return c;
	},

	invert: function(a) {
		var b = new Array(a.length);
		for(var i = 0; i < a.length; i++) { b[i] = -a[i]; }
		return b;
	},

	distance: function(a, b) {
		return Math.sqrt(Math.pow(b[0]-a[0], 2) + Math.pow(b[1]-a[1], 2));
	}
};
