/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.Chart");
dojo.provide("dojo.widget.Chart.PlotTypes");
dojo.provide("dojo.widget.Chart.DataSeries");

dojo.require("dojo.widget.*");
dojo.require("dojo.graphics.color");
dojo.require("dojo.graphics.color.hsl");
dojo.widget.tags.addParseTreeHandler("dojo:chart");

dojo.widget.Chart = function(){
	dojo.widget.Widget.call(this);
	this.widgetType = "Chart";
	this.isContainer = false;
	this.series = [];
	// FIXME: why is this a mixin method?
	this.assignColors = function(){
		var hue=30;
		var sat=120;
		var lum=120;
		var steps = Math.round(330/this.series.length);

		for(var i=0; i<this.series.length; i++){
			var c=dojo.graphics.color.hsl2rgb(hue,sat,lum);
			if(!this.series[i].color){
				this.series[i].color = dojo.graphics.color.rgb2hex(c[0],c[1],c[2]);
			}
			hue += steps;
		}
	};
}
dojo.inherits(dojo.widget.Chart, dojo.widget.Widget);

dojo.widget.Chart.PlotTypes = {
	Bar:"bar",
	Line:"line",
	Scatter:"scatter",
	Bubble:"bubble"
};

/*
 *	Every chart has a set of data series; this is the series.  Note that each
 *	member of value is an object and in the minimum has 2 properties: .x and
 *	.value.
 */
dojo.widget.Chart.DataSeries = function(key, label, plotType, color){
	// FIXME: why the hell are plot types specified neumerically? What is this? C?
	this.id = "DataSeries"+dojo.widget.Chart.DataSeries.count++;
	this.key = key;
	this.label = label||this.id;
	this.plotType = plotType||0;
	this.color = color;
	this.values = [];
};

dojo.lang.extend(dojo.widget.Chart.DataSeries, {
	add: function(v){
		if(v.x==null||v.value==null){
			dojo.raise("dojo.widget.Chart.DataSeries.add: v must have both an 'x' and 'value' property.");
		}
		this.values.push(v);
	},

	clear: function(){
		this.values=[];
	},

	createRange: function(len){
		var idx = this.values.length-1;
		var length = (len||this.values.length);
		return { "index": idx, "length": length, "start":Math.max(idx-length,0) };
	},

	//	trend values
	getMean: function(len){
		var range = this.createRange(len);
		if(range.index<0){ return 0; }
		var t = 0;
		var c = 0;
		for(var i=range.index; i>=range.start; i--){
			var n = parseFloat(this.values[i].value);
			if(!isNaN(n)){ t += n; c++; }
		}
		t /= Math.max(c,1);
		return t;
	},

	getMovingAverage: function(len){
		var range = this.createRange(len);
		if(range.index<0){ return 0; }
		var t = 0;
		var c = 0;
		for(var i=range.index; i>=range.start; i--){
			var n = parseFloat(this.values[i].value);
			if(!isNaN(n)){ t += n; c++; }
		}
		t /= Math.max(c,1);
		return t;
	},

	getVariance: function(len){
		var range = this.createRange(len);
		if(range.index < 0){ return 0; }
		var t = 0; // FIXME: for tom: wtf are t, c, and s?
		var s = 0;
		var c = 0;
		for(var i=range.index; i>=range.start; i--){
			var n = parseFloat(this.values[i].value);
			if(!isNaN(n)){
				t += n;
				s += Math.pow(n,2);
				c++;
			}
		}
		return (s/c)-Math.pow(t/c,2);
	},

	getStandardDeviation: function(len){
		return Math.sqrt(this.getVariance(len));
	},

	getMax: function(len){
		var range = this.createRange(len);
		if(range.index < 0){ return 0; }
		var t = 0;
		for (var i=range.index; i>=range.start; i--){
			var n=parseFloat(this.values[i].value);
			if (!isNaN(n)){
				t=Math.max(n,t);
			}
		}
		return t;
	},

	getMin: function(len){
		var range=this.createRange(len);
		if(range.index < 0){ return 0; }
		var t = 0;
		for(var i=range.index; i>=range.start; i--){
			var n = parseFloat(this.values[i].value);
			if(!isNaN(n)){
				t=Math.min(n,t);
			}
		}
		return t;
	},

	getMedian: function(len){
		var range = this.createRange(len);

		if(range.index<0){ return 0; }

		var a = [];
		for (var i=range.index; i>=range.start; i--){
			var n=parseFloat(this.values[i].value);
			if (!isNaN(n)){
				var b=false;
				for(var j=0; j<a.length&&!b; j++){
					if (n==a[j]) b=true; 
				}
				if(!b){ a.push(n); }
			}
		}
		a.sort();
		if(a.length>0){ return a[Math.ceil(a.length/2)]; }
		return 0;
	},

	getMode: function(len){
		var range=this.createRange(len);
		if(range.index<0){ return 0; }
		var o = {};
		var ret = 0
		var m = 0;
		for(var i=range.index; i>=range.start; i--){
			var n=parseFloat(this.values[i].value);
			if(!isNaN(n)){
				if (!o[this.values[i].value]) o[this.values[i].value] = 1;
				else o[this.values[i].value]++;
			}
		}
		for(var p in o){
			if(m<o[p]){ m=o[p]; ret=p; }
		}
		return parseFloat(ret);
	}
});

dojo.requireIf(dojo.render.svg.support.builtin, "dojo.widget.svg.Chart");
dojo.requireIf(dojo.render.html.ie, "dojo.widget.vml.Chart");
