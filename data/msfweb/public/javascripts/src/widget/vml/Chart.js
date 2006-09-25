/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.vml.Chart");

dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.widget.Chart");
dojo.require("dojo.math");
dojo.require("dojo.html");
//dojo.require("dojo.vml");
dojo.require("dojo.graphics.color");

dojo.widget.vml.Chart=function(){
	dojo.widget.Chart.call(this);
	dojo.widget.HtmlWidget.call(this);
};
dojo.inherits(dojo.widget.vml.Chart, dojo.widget.HtmlWidget);
dojo.lang.extend(dojo.widget.vml.Chart, {
	//	widget props
	templatePath:null,
	templateCssPath:null,

	//	state
	_isInitialized:false,
	hasData:false,

	//	chart props
	vectorNode:null,
	plotArea:null,
	dataGroup:null,
	axisGroup:null,

	properties:{
		height:400,	//	defaults, will resize to the domNode.
		width:600,
		plotType:null,
		padding:{
			top:10,
			bottom:2,
			left:60,
			right:30
		},
		axes:{
			x:{
				plotAt:0,
				label:"",
				unitLabel:"",
				unitType:Number,
				nUnitsToShow:10,
				range:{
					min:0,
					max:200
				}
			},
			y:{
				plotAt:0,
				label:"",
				unitLabel:"",
				unitType:Number,
				nUnitsToShow:10,
				range:{
					min:0,
					max:200
				}
			}
		}
	},
	
	fillInTemplate:function(args,frag){
		this.initialize();
		this.render();
	},
	parseData:function(){
	},
	initialize:function(){
		//	parse the data first.
		this.parseData();
	
		// render the body of the chart, not the chart data.
		if(this.vectorNode){ this.destroy(); }
		this.vectorNode=document.createElement("div");
		this.vectorNode.style.width=this.properties.width+"px";
		this.vectorNode.style.height=this.properties.height+"px";
		this.vectorNode.style.position="relative";
		this.domNode.appendChild(this.vectorNode);

		var plotWidth=this.properties.width-this.properties.padding.left-this.properties.padding.right;
		var plotHeight=this.properties.height-this.properties.padding.top-this.properties.padding.bottom;

		this.plotArea=document.createElement("div");
		this.plotArea.style.position="absolute";
		this.plotArea.style.backgroundColor="#fff";
		this.plotArea.style.top=(this.properties.padding.top)-2+"px";
		this.plotArea.style.left=(this.properties.padding.left-1)+"px";
		this.plotArea.style.width=plotWidth+"px";
		this.plotArea.style.height=plotHeight+"px";
		this.vectorNode.appendChild(this.plotArea);
		
		this.dataGroup=document.createElement("div");
		this.dataGroup.style.position="relative";
		this.plotArea.appendChild(this.dataGroup);

		//	clipping rects, what a fucking pain.
		var bg=this.domNode.style.backgroundColor;
		var r=document.createElement("v:rect");
		r.setAttribute("fillcolor", bg);
		r.setAttribute("stroked", "false");
		r.style.position="absolute";
		r.style.top=(-1*this.properties.padding.top)-1+"px";
		r.style.left=(-1*this.properties.padding.left)+"px";
		r.style.width=(this.properties.width-3)+"px";
		r.style.height=(this.properties.padding.top)-2+"px";
		this.vectorNode.appendChild(r);

		r=document.createElement("v:rect");
		r.setAttribute("fillcolor", bg);
		r.setAttribute("stroked", "false");
		r.style.position="absolute";
		r.style.top=plotHeight-2+"px";
		r.style.left=(-1*this.properties.padding.left)+"px";
		r.style.width=(this.properties.width-3)+"px";
		r.style.height=(this.properties.padding.bottom)-2+"px"; // fixme: check this.
		this.vectorNode.appendChild(r);

		r=document.createElement("v:rect");
		r.setAttribute("fillcolor", bg);
		r.setAttribute("stroked", "false");
		r.style.position="absolute";
		r.style.top="-2px";
		r.style.left=(-1*this.properties.padding.left)+"px";
		r.style.width=(this.properties.padding.left-1)+"px";
		r.style.height=plotHeight+"px";
		this.vectorNode.appendChild(r);
		
		r=document.createElement("v:rect");
		r.setAttribute("fillcolor", bg);
		r.setAttribute("stroked", "false");
		r.style.position="absolute";
		r.style.top="-2px";
		r.style.right=(-1*this.properties.padding.right)+1+"px";
		r.style.width=(this.properties.padding.right-1)+"px";
		r.style.height=plotHeight+"px";
		this.vectorNode.appendChild(r);
		//	end clipping rects.  god that sucks, i wish VML had clipping outside of that crap vmlframe...

		this.axisGroup=document.createElement("div");
		this.axisGroup.style.position="relative";
		this.plotArea.appendChild(this.axisGroup);

		var stroke=1;

		//	x axis
		var line=document.createElement("v:line");
		var y=dojo.widget.vml.Chart.Plotter.getY(this.properties.axes.x.plotAt, this);
		line.setAttribute("from", this.properties.padding.left-stroke + "," + y);
		line.setAttribute("to", plotWidth + "," + y);
		line.style.position="absolute";
		line.style.antialias="false";
		line.setAttribute("strokecolor", "#666");
		line.setAttribute("strokeweight", stroke*2+"px");
		this.axisGroup.appendChild(line);

		//	y axis
		var line=document.createElement("v:line");
		var y=dojo.widget.vml.Chart.Plotter.getX(this.properties.axes.y.plotAt, this);
		line.setAttribute("from", y+","+this.properties.padding.top);
		line.setAttribute("to", y+","+this.properties.height-this.properties.padding.bottom);
		line.style.position="absolute";
		line.style.antialias="false";
		line.setAttribute("strokecolor", "#666");
		line.setAttribute("strokeweight", stroke*2+"px");
		this.axisGroup.appendChild(line);
		
		//	labels
		var size=10;

		//	x axis labels.
		var t=document.createElement("div");
		t.style.position="absolute";
		t.style.top=(this.properties.height-this.properties.padding.bottom+size+2)+"px";
		t.style.left=this.properties.padding.left+"px";
		t.style.fontFamily="sans-serif";
		t.style.fontSize=size+"px";
		t.innerHTML=dojo.math.round(parseFloat(this.properties.axes.x.range.min),2);
		this.axisGroup.appendChild(t);

		t=document.createElement("div");
		t.style.position="absolute";
		t.style.top=(this.properties.height-this.properties.padding.bottom+size+2)+"px";
		t.style.left=(this.properties.width-this.properties.padding.right-(size/2))+"px";
		t.style.fontFamily="sans-serif";
		t.style.fontSize=size+"px";
		t.innerHTML=dojo.math.round(parseFloat(this.properties.axes.x.range.max),2);
		this.axisGroup.appendChild(t);

		//	y axis labels.
		t=document.createElement("div");
		t.style.position="absolute";
		t.style.top=-1*(size/2)+"px";
		t.style.right=(plotWidth+4)+"px";
		t.style.fontFamily="sans-serif";
		t.style.fontSize=size+"px";
		t.innerHTML=dojo.math.round(parseFloat(this.properties.axes.y.range.max),2);
		this.axisGroup.appendChild(t);
		
		t=document.createElement("div");
		t.style.position="absolute";
		t.style.top=(this.properties.height-this.properties.padding.bottom)+"px";
		t.style.right=(plotWidth+4)+"px";
		t.style.fontFamily="sans-serif";
		t.style.fontSize=size+"px";
		t.innerHTML=dojo.math.round(parseFloat(this.properties.axes.y.range.min),2);
		this.axisGroup.appendChild(t);
		
		//	this is last.
		this.assignColors();
		this._isInitialized=true;
	},
	destroy:function(){
		while(this.domNode.childNodes.length>0){
			this.domNode.removeChild(this.domNode.childNodes[0]);
		}
		this.vectorNode=this.plotArea=this.dataGroup=this.axisGroup=null;
	},
	render:function(){
		if (this.dataGroup){
			while(this.dataGroup.childNodes.length>0){
				this.dataGroup.removeChild(this.dataGroup.childNodes[0]);
			}
		} else {
			this.initialize();
		}
		for(var i=0; i<this.series.length; i++){
			dojo.widget.vml.Chart.Plotter.plot(this.series[i], this);
		}
	}
});

dojo.widget.vml.Chart.Plotter=new function(){
	var _this=this;
	var plotters = {};
	var types=dojo.widget.Chart.PlotTypes;
	
	this.getX=function(value, chart){
		var v=parseFloat(value);
		var min=chart.properties.axes.x.range.min;
		var max=chart.properties.axes.x.range.max;
		var ofst=0-min;
		min+=ofst; max+=ofst; v+=ofst;

		var xmin=chart.properties.padding.left;
		var xmax=chart.properties.width-chart.properties.padding.right;
		var x=(v*((xmax-xmin)/max))+xmin;
		return x;
	};
	this.getY=function(value, chart){
		var v=parseFloat(value);
		var max=chart.properties.axes.y.range.max;
		var min=chart.properties.axes.y.range.min;
		var ofst=0;
		if(min<0)ofst+=Math.abs(min);
		min+=ofst; max+=ofst; v+=ofst;
		
		var ymin=chart.properties.height-chart.properties.padding.bottom;
		var ymax=chart.properties.padding.top;
		var y=(((ymin-ymax)/(max-min))*(max-v))+ymax;
		return y;
	};

	this.addPlotter=function(name, func){
		plotters[name]=func;
	};
	this.plot=function(series, chart){
		if (series.values.length==0) return;
		if (series.plotType && plotters[series.plotType]){
			return plotters[series.plotType](series, chart);
		}
		else if (chart.plotType && plotters[chart.plotType]){
			return plotters[chart.plotType](series, chart);
		}
	};

	//	plotting
	plotters[types.Bar]=function(series, chart){
		var space=1;
		var lastW = 0;
		for (var i=0; i<series.values.length; i++){
			var x=_this.getX(series.values[i].x, chart);
			var w;
			if (i==series.values.length-1){
				w=lastW;
			} else{
				w=_this.getX(series.values[i+1].x, chart)-x-space;
				lastW=w;
			}
			x-=(w/2);

			var yA=_this.getY(chart.properties.axes.x.plotAt, chart);
			var y=_this.getY(series.values[i].value, chart);
			var h=Math.abs(yA-y);
			if (parseFloat(series.values[i].value)<chart.properties.axes.x.plotAt){
				var oy=yA;
				yA=y;
				y=oy;
			}

			var bar=document.createElement("v:rect");
			bar.style.position="absolute";
			bar.style.top=x+"px";
			bar.style.left=y+"px";
			bar.style.width=w+"px";
			bar.style.height=h+"px";
			bar.setAttribute("fillColor", series.color);
			bar.setAttribute("title", series.label + ": " + series.values[i].value);
			bar.setAttribute("coordsize", chart.properties.width + "," + chart.properties.height);
			var fill=document.createElement("v:fill");
			fill.setAttribute("opacity", "0.9");
			bar.appendChild(fill);
			chart.dataGroup.appendChild(bar);
		}
	};	
	plotters[types.Line]=function(series, chart){
		var tension=3;

		var line=document.createElement("v:shape");
		line.setAttribute("strokeweight", "2px");
		line.setAttribute("strokecolor", series.color);
		line.setAttribute("fillcolor", "none");
		line.setAttribute("filled", "false");
		line.setAttribute("title", series.label);
		line.setAttribute("coordsize", chart.properties.width + "," + chart.properties.height);
		line.style.position="absolute";
		line.style.top="0px";
		line.style.left="0px";
		line.style.width= chart.properties.width+"px";
		line.style.height=chart.properties.height+"px";
		var stroke=document.createElement("v:stroke");
		stroke.setAttribute("opacity", "0.85");
		line.appendChild(stroke);

		var path = [];
		for (var i=0; i<series.values.length; i++){
			var x = _this.getX(series.values[i].x, chart)
			var y = _this.getY(series.values[i].value, chart);

			if (i==0){
				path.push("m");
				path.push(x+","+y);
			}else{
				var lastx=_this.getX(series.values[i-1].x, chart);
				var lasty=_this.getY(series.values[i-1].value, chart);
				var dx=x-lastx;
				
				path.push("v");
				var cx=x-(tension-1)*(dx/tension);
				path.push(cx+",0");
				cx=x-(dx/tension);
				path.push(cx+","+y-lasty);
				path.push(dx, y-lasty);
			}
		}
		line.setAttribute("path", path.join(" ")+" e");
		chart.dataGroup.appendChild(line);
	};
	plotters[types.Scatter]=function(series, chart){
		var r=8;
		for (var i=0; i<series.values.length; i++){
			var x=_this.getX(series.values[i].x, chart);
			var y=_this.getY(series.values[i].value, chart);
			var mod=r/2;

			var point=document.createElement("v:rect");
			point.setAttribute("fillcolor", series.color);
			point.setAttribute("strokecolor", series.color);
			point.setAttribute("title", series.label + ": " + series.values[i].value);
			point.style.position="absolute";
			point.style.rotation="45";
			point.style.top=(y-mod)+"px";
			point.style.left=(x-mod)+"px";
			point.style.width=r+"px";
			point.style.height=r+"px";
			var fill=document.createElement("v:fill");
			fill.setAttribute("opacity", "0.5");
			point.appendChild(fill);
			chart.dataGroup.appendChild(point);
		}
	};	
	plotters[types.Bubble]=function(series, chart){
		//	added param for series[n].value: size
		var minR=1;
		
		//	do this off the x axis?
		var min=chart.properties.axes.x.range.min;
		var max=chart.properties.axes.x.range.max;
		var ofst=0-min;

		min+=ofst; max+=ofst;
		var xmin=chart.properties.padding.left;
		var xmax=chart.properties.width-chart.properties.padding.right;
		var factor=(max-min)/(xmax-xmin)*25;
		
		for (var i=0; i<series.values.length; i++){
			var size = series.values[i].size;
			if (isNaN(parseFloat(size))) size=minR;
			var mod=(parseFloat(size)*factor)/2;

			var point=document.createElement("v:oval");
			point.setAttribute("strokecolor", series.color);
			point.setAttribute("fillcolor", series.color);
			point.setAttribute("title", series.label + ": " + series.values[i].value + " (" + size + ")");
			point.style.position="absolute";
			point.style.top=(_this.getY(series.values[i].value, chart)-mod) + "px";
			point.style.left=(_this.getX(series.values[i].x, chart)-mod) + "px";
			point.style.width=mod+"px";
			point.style.height=mod+"px";
			chart.dataGroup.appendChild(point);
		}
	};
}();
