/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.GoogleMap");
dojo.require("dojo.event.*");
dojo.require("dojo.html");
dojo.require("dojo.math");
dojo.require("dojo.uri.Uri");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.widget.GoogleMap");

(function(){
	var gkey = djConfig["gMapKey"]||djConfig["googleMapKey"];

	//	the Google API key mechanism sucks.  We're hardcoding here for love and affection but I don't like it.
	var uri=new dojo.uri.Uri(window.location.href);
	if(uri.host=="www.dojotoolkit.org"){
		gkey="ABQIAAAACUNdgv_7FGOmUslbm9l6_hRqjp7ri2mNiOEYqetD3xnFHpt5rBSjszDd1sdufPyQKUTyCf_YxoIxvw";
	}
	else if(uri.host=="blog.dojotoolkit.org"){
		gkey="ABQIAAAACUNdgv_7FGOmUslbm9l6_hSkep6Av1xaMhVn3yCLkorJeXeLARQ6fammI_P3qSGleTJhoI5_1JmP_Q";
	}
	else if(uri.host=="archive.dojotoolkit.org"){
		gkey="ABQIAAAACUNdgv_7FGOmUslbm9l6_hTaQpDt0dyGLIHbXMPTzg1kWeAfwRTwZNyrUfbfxYE9yIvRivEjcXoDTg";
	}
	else if(uri.host=="dojotoolkit.org"){
		gkey="ABQIAAAACUNdgv_7FGOmUslbm9l6_hSaOaO_TgJ5c3mtQFnk5JO2zD5dZBRZk-ieqVs7BORREYNzAERmcJoEjQ";
	}

	if(!dojo.hostenv.post_load_){
		var tag = "<scr"+"ipt src='http://maps.google.com/maps?file=api&amp;v=2&amp;key="+gkey+"'></scri"+"pt>";
		if(!dj_global["GMap2"]){ // prevent multi-inclusion
			document.write(tag);
		}
	}else{
		dojo.debug("cannot initialize map system after the page has been loaded! Please either manually include the script block provided by Google in your page or require() the GoogleMap widget before onload has fired");
	}
})();

dojo.widget.html.GoogleMap=function(){
	dojo.widget.HtmlWidget.call(this);
	dojo.widget.GoogleMap.call(this);

	var gm=dojo.widget.GoogleMap;

	this.map=null;
	this.data=[];
	this.datasrc="";
	// FIXME: this is pehraps the stupidest way to specify this enum I can think of
	this.controls=[gm.Controls.LargeMap,gm.Controls.Scale,gm.Controls.MapType];
};
dojo.inherits(dojo.widget.html.GoogleMap, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.html.GoogleMap, {
	templatePath:null,
	templateCssPath:null,

	setControls:function(){
		var c=dojo.widget.GoogleMap.Controls;
		for(var i=0; i<this.controls.length; i++){
			var type=this.controls[i];
			switch(type){
				case c.LargeMap:{
					this.map.addControl(new GLargeMapControl());
					break;
				}
				case c.SmallMap:{
					this.map.addControl(new GSmallMapControl());
					break;
				}
				case c.SmallZoom:{
					this.map.addControl(new GSmallZoomControl());
					break;
				}
				case c.Scale:{
					this.map.addControl(new GScaleControl());
					break;
				}
				case c.MapType:{
					this.map.addControl(new GMapTypeControl());
					break;
				}
				case c.Overview:{
					this.map.addControl(new GOverviewMapControl());
					break;
				}
				default:{
					break;
				}
			}
		}
	},
	
	findCenter:function(bounds){
		var clat=(bounds.getNorthEast().lat()+bounds.getSouthWest().lat())/2;
		var clng=(bounds.getNorthEast().lng()+bounds.getSouthWest().lng())/2;
		return (new GLatLng(clat,clng));
	},

	createPinpoint:function(pt,overlay){
		var m=new GMarker(pt);
		if(overlay){
			GEvent.addListener(m,"click",function(){
				m.openInfoWindowHtml("<div>"+overlay+"</div>");
			});
		}
		return m;
	},

	parse:function(table){
		this.data=[];

		//	get the column indices
		var h=table.getElementsByTagName("thead")[0];
		if(!h){
			return;
		}

		var a=[];
		var cols=h.getElementsByTagName("td");
		if(cols.length==0){
			cols=h.getElementsByTagName("th");
		}
		for(var i=0; i<cols.length; i++){
			var c=cols[i].innerHTML.toLowerCase();
			if(c=="long") c="lng";
			a.push(c);
		}
		
		//	parse the data
		var b=table.getElementsByTagName("tbody")[0];
		if(!b){
			return;
		}
		for(var i=0; i<b.childNodes.length; i++){
			if(!(b.childNodes[i].nodeName&&b.childNodes[i].nodeName.toLowerCase()=="tr")){
				continue;
			}
			var cells=b.childNodes[i].getElementsByTagName("td");
			var o={};
			for(var j=0; j<a.length; j++){
				var col=a[j];
				if(col=="lat"||col=="lng"){
					o[col]=parseFloat(cells[j].innerHTML);					
				}else{
					o[col]=cells[j].innerHTML;
				}
			}
			this.data.push(o);
		}
	},
	render:function(){
		var bounds=new GLatLngBounds();
		var d=this.data;
		var pts=[];
		for(var i=0; i<d.length; i++){
			bounds.extend(new GLatLng(d[i].lat,d[i].lng));
		}

		this.map.setCenter(this.findCenter(bounds), this.map.getBoundsZoomLevel(bounds));

		for(var i=0; i<this.data.length; i++){
			var p=new GLatLng(this.data[i].lat,this.data[i].lng);
			var d=this.data[i].description||null;
			var m=this.createPinpoint(p,d);
			this.map.addOverlay(m);
		}
	},
	

	initialize:function(args, frag){
		if(!GMap2){
			dojo.raise("dojo.widget.GoogleMap: The Google Map script must be included (with a proper API key) in order to use this widget.");
		}
		if(this.datasrc){
			this.parse(dojo.byId(this.datasrc));
		}
		else if(this.domNode.getElementsByTagName("table")[0]){
			this.parse(this.domNode.getElementsByTagName("table")[0]);
		}
	},
	postCreate:function(){
		//	clean the domNode before creating the map.
		while(this.domNode.childNodes.length>0){
			this.domNode.removeChild(this.domNode.childNodes[0]);
		}
		this.map=new GMap2(this.domNode);
		this.render();
		this.setControls();
	}
});
