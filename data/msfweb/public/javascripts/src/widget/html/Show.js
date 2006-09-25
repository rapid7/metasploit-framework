/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.Show");

dojo.require("dojo.widget.*");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.widget.Show");
dojo.require("dojo.uri.Uri");
dojo.require("dojo.event");
dojo.require("dojo.animation.Animation");
dojo.require("dojo.math.curves");
dojo.require("dojo.html");
dojo.require("dojo.lang.common");
dojo.require("dojo.lang.func");

dojo.widget.defineWidget(
	"dojo.widget.html.Show",
	dojo.widget.HtmlWidget,
	null,
	"html",
	function(){
		dojo.widget.Show.call(this);
	}
);
dojo.lang.extend(dojo.widget.html.Show, dojo.widget.Show.prototype);
dojo.lang.extend(dojo.widget.html.Show, {
	body: null,
	nav: null,
	hider: null,
	select: null,
	option: null,
	inNav: false,
	templatePath: dojo.uri.dojoUri("src/widget/templates/HtmlShow.html"),
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlShow.css"),
	fillInTemplate: function(args, frag){
		var source = this.getFragNodeRef(frag);
		this.sourceNode = document.body.appendChild(source.cloneNode(true));
		for(var i = 0, child; child = this.sourceNode.childNodes[i]; i++){
			if(child.tagName && child.getAttribute("dojotype").toLowerCase() == "showslide"){
				child.className = "dojoShowPrintSlide";
				child.innerHTML = "<h1>" + child.title + "</h1>" + child.innerHTML;
			}
		}
		this.sourceNode.className = "dojoShowPrint";
		this.sourceNode.style.display = "none";
		
		dojo.event.connect(document, "onclick", this, "gotoSlideByEvent");
		dojo.event.connect(document, "onkeypress", this, "gotoSlideByEvent");
		dojo.event.connect(window, "onresize", this, "resizeWindow");
		dojo.event.connect(this.nav, "onmousemove", this, "popUpNav");
	},
	postCreate: function(){		
		this._slides = [];
		for(var i = 0, child; child = this.children[i]; i++){
			if(child.widgetType == "ShowSlide"){
				this._slides.push(child);
				this.option.text = child.title;
				this.option.parentNode.insertBefore(this.option.cloneNode(true), this.option);
			}
		}
		this.option.parentNode.removeChild(this.option);

		document.body.style.display = "block";
		this.resizeWindow();
		this.gotoSlide(0);
	},
	gotoSlide: function(/*int*/ slide){
		if(slide == this._slide){
			return;
		}

		if(!this._slides[slide]){
			// slide: string
			for(var i = 0, child; child = this._slides[i]; i++){
				if(child.title == slide){
					slide = i;
					break;
				}
			}
		}
		
		if(!this._slides[slide]){
			return;
		}
		
		if(this._slide != -1){
			while(this._slides[this._slide].previousAction()){}
		}
		
		this._slide = slide;
		this.select.selectedIndex = slide;
		while(this.contentNode.hasChildNodes()){ this.contentNode.removeChild(this.contentNode.firstChild); }
		this.contentNode.appendChild(this._slides[slide].domNode);
	},
	gotoSlideByEvent: function(/*Event*/ event){
		var node = event.target;
		var type = event.type;
		if(type == "click"){
			if(node.tagName == "OPTION"){
				this.gotoSlide(node.index);
			}else if(node.tagName == "SELECT"){
				this.gotoSlide(node.selectedIndex);
			}else if(node.tagName != "A"){
				this.nextSlide(event);
			}
		}else if(type == "keypress"){
			var key = event.keyCode;
			var ch = event.charCode;
			if(key == 63234 || key == 37){
				this.previousSlide(event);
			}else if(key == 63235 || key == 39 || ch == 32){
				this.nextSlide(event);
			}
		}
	},
	nextSlide: function(/*Event?*/ event){
		this.stopEvent(event);
		return dojo.widget.Show.prototype.nextSlide.call(this, event);
	},
	previousSlide: function(/*Event?*/ event){
		this.stopEvent(event);
		return dojo.widget.Show.prototype.previousSlide.call(this, event);
	},
	stopEvent: function(/*Event*/ ev){
		if(window.event){
			ev.returnValue = false;
			ev.cancelBubble = true;
		}else{
			ev.preventDefault();
			ev.stopPropagation();
		}
	},
	popUpNav: function(){
		if(!this.inNav){
			dojo.widget.Show.node = this.nav;
			var anim = new dojo.animation.Animation(new dojo.math.curves.Line([5], [30]), 250, -1);
			dojo.event.connect(anim, "onAnimate", function(e) {
				dojo.widget.Show.node.style.height = e.x + "px";
			});
			dojo.event.connect(anim, "onEnd", function(e) {
				dojo.widget.Show.node.style.height = e.x + "px";
			});
			anim.play(true);
		}
		clearTimeout(this.inNav);
		this.inNav = setTimeout(dojo.lang.hitch(this, "hideNav"), 2000);
	},
	hideNav: function(){
		clearTimeout(this.inNav);
		this.inNav = false;

		dojo.widget.Show.node = this.nav;
		var anim = new dojo.animation.Animation(new dojo.math.curves.Line([30], [5]), 250, 1);
		dojo.event.connect(anim, "onAnimate", function(e) {
			dojo.widget.Show.node.style.height = e.x + "px";
		});
		dojo.event.connect(anim, "onEnd", function(e) {
			dojo.widget.Show.node.style.height = e.x + "px";
		});
		anim.play(true);
	},
	resizeWindow: function(/*Event*/ ev){
		document.body.style.height = "auto";
		var h = Math.max(
			document.documentElement.scrollHeight || document.body.scrollHeight,
			dojo.html.getViewportHeight());
		document.body.style.height = h + "px";
	}
});