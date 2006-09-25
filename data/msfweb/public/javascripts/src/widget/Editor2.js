/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/* TODO:
 * - font selector
 * - test, bug fix, more features :)
*/
dojo.provide("dojo.widget.Editor2");
dojo.provide("dojo.widget.html.Editor2");
dojo.require("dojo.io.*");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.RichText");
dojo.require("dojo.widget.Editor2Toolbar");
// dojo.require("dojo.widget.ColorPalette");
// dojo.require("dojo.string.extras");

dojo.widget.defineWidget(
	"dojo.widget.html.Editor2",
	dojo.widget.html.RichText,
	{
		saveUrl: "",
		saveMethod: "post",
		saveArgName: "editorContent",
		closeOnSave: false,
		shareToolbar: false,
		toolbarAlwaysVisible: false,
		htmlEditing: false,
		_inHtmlMode: false,
		_htmlEditNode: null,

		commandList: dojo.widget.html.Editor2Toolbar.prototype.commandList,
		toolbarWidget: null,
		scrollInterval: null,
		

		editorOnLoad: function(){
			var toolbars = dojo.widget.byType("Editor2Toolbar");
			if((!toolbars.length)||(!this.shareToolbar)){
				var tbOpts = {};
				tbOpts.templatePath = dojo.uri.dojoUri("src/widget/templates/HtmlEditorToolbarOneline.html");
				this.toolbarWidget = dojo.widget.createWidget("Editor2Toolbar", 
										tbOpts, this.domNode, "before");
				dojo.event.connect(this, "destroy", this.toolbarWidget, "destroy");
				this.toolbarWidget.hideUnusableButtons(this);

				if(this.object){
					this.tbBgIframe = new dojo.html.BackgroundIframe(this.toolbarWidget.domNode);
					this.tbBgIframe.iframe.style.height = "30px";
				}

				// need to set position fixed to wherever this thing has landed
				if(this.toolbarAlwaysVisible){
					var src = document["documentElement"]||window;
					this.scrollInterval = setInterval(dojo.lang.hitch(this, "globalOnScrollHandler"), 100);
					// dojo.event.connect(src, "onscroll", this, "globalOnScrollHandler");
					dojo.event.connect("before", this, "destroyRendering", this, "unhookScroller");
				}
			}else{
				// FIXME: 	should we try harder to explicitly manage focus in
				// 			order to prevent too many editors from all querying
				// 			for button status concurrently?
				// FIXME: 	selecting in one shared toolbar doesn't clobber
				// 			selection in the others. This is problematic.
				this.toolbarWidget = toolbars[0];
			}
			dojo.event.topic.registerPublisher("Editor2.clobberFocus", this.editNode, "onfocus");
			// dojo.event.topic.registerPublisher("Editor2.clobberFocus", this.editNode, "onclick");
			dojo.event.topic.subscribe("Editor2.clobberFocus", this, "setBlur");
			dojo.event.connect(this.editNode, "onfocus", this, "setFocus");
			dojo.event.connect(this.toolbarWidget.linkButton, "onclick", 
				dojo.lang.hitch(this, function(){
					var range;
					if(this.document.selection){
						range = this.document.selection.createRange().text;
					}else if(dojo.render.html.mozilla){
						range = this.window.getSelection().toString();
					}
					if(range.length){
						this.toolbarWidget.exec("createlink", 
							prompt("Please enter the URL of the link:", "http://"));
					}else{
						alert("Please select text to link");
					}
				})
			);

			var focusFunc = dojo.lang.hitch(this, function(){ 
				if(dojo.render.html.ie){
					this.editNode.focus();
				}else{
					this.window.focus(); 
				}
			});

			dojo.event.connect(this.toolbarWidget, "formatSelectClick", focusFunc);
			dojo.event.connect(this, "execCommand", focusFunc);

			if(this.htmlEditing){
				var tb = this.toolbarWidget.htmltoggleButton;
				if(tb){
					tb.style.display = "";
					dojo.event.connect(this.toolbarWidget, "htmltoggleClick",
										this, "toggleHtmlEditing");
				}
			}
		},

		toggleHtmlEditing: function(){
			if(!this._inHtmlMode){
				this._inHtmlMode = true;
				this.toolbarWidget.highlightButton("htmltoggle");
				if(!this._htmlEditNode){
					this._htmlEditNode = document.createElement("textarea");
					dojo.html.insertBefore(this._htmlEditNode, this.domNode);
				}
				this._htmlEditNode.style.display = "";
				this._htmlEditNode.style.width = "100%";
				this._htmlEditNode.style.height = dojo.style.getInnerHeight(this.editNode)+"px";
				this._htmlEditNode.value = this.editNode.innerHTML;
				this.domNode.style.display = "none";
			}else{
				this._inHtmlMode = false;
				this.domNode.style.display = "";
				this.toolbarWidget.unhighlightButton("htmltoggle");
				dojo.lang.setTimeout(this, "replaceEditorContent", 1, this._htmlEditNode.value);
				this._htmlEditNode.style.display = "none";
				this.editNode.focus();
			}
		},

		setFocus: function(){
			// dojo.debug("setFocus:", this);
			dojo.event.connect(this.toolbarWidget, "exec", this, "execCommand");
		},

		setBlur: function(){
			// dojo.debug("setBlur:", this);
			dojo.event.disconnect(this.toolbarWidget, "exec", this, "execCommand");
		},

		_scrollSetUp: false,
		_fixEnabled: false,
		_scrollThreshold: false,
		_handleScroll: true,
		globalOnScrollHandler: function(){
			var isIE = dojo.render.html.ie;
			if(!this._handleScroll){ return; }
			var ds = dojo.style;
			var tdn = this.toolbarWidget.domNode;
			var db = document["body"];
			var totalHeight = ds.getOuterHeight(tdn);
			if(!this._scrollSetUp){
				this._scrollSetUp = true;
				var editorWidth =  ds.getOuterWidth(this.domNode); 
				this._scrollThreshold = ds.abs(tdn, false).y;
				// dojo.debug("threshold:", this._scrollThreshold);
				if((isIE)&&(db)&&(ds.getStyle(db, "background-image")=="none")){
					with(db.style){
						backgroundImage = "url(" + dojo.uri.dojoUri("src/widget/templates/images/blank.gif") + ")";
						backgroundAttachment = "fixed";
					}
				}
			}

			var scrollPos = (window["pageYOffset"]) ? window["pageYOffset"] : (document["documentElement"]||document["body"]).scrollTop;

			// FIXME: need to have top and bottom thresholds so toolbar doesn't keep scrolling past the bottom
			if(scrollPos > this._scrollThreshold){
				// dojo.debug(scrollPos);
				if(!this._fixEnabled){
					this.domNode.style.marginTop = totalHeight+"px";
					if(isIE){
						// FIXME: should we just use setBehvior() here instead?
						var cl = dojo.style.abs(tdn).x;
						document.body.appendChild(tdn);
						tdn.style.left = cl+dojo.style.getPixelValue(document.body, "margin-left")+"px";
						dojo.html.addClass(tdn, "IEFixedToolbar");
						if(this.object){
							dojo.html.addClass(this.tbBgIframe, "IEFixedToolbar");
						}
						
					}else{
						with(tdn.style){
							position = "fixed";
							top = "0px";
						}
					}
					tdn.style.zIndex = 1000;
					this._fixEnabled = true;
				}
				// if we're showing the floating toolbar, make sure that if
				// we've scrolled past the bottom of the editor that we hide
				// the toolbar for this instance of the editor.

				// TODO: when we get multiple editor toolbar support working
				// correctly, ensure that we check this against the scroll
				// position of the bottom-most editor instance.
				if(!dojo.render.html.safari){
					// safari reports a bunch of things incorrectly here
					var eHeight = (this.height) ? parseInt(this.height) : ((this.object) ? dojo.style.getInnerHeight(this.editNode) : this._lastHeight);
					if(scrollPos > (this._scrollThreshold+eHeight)){
						tdn.style.display = "none";
					}else{
						tdn.style.display = "";
					}
				}

			}else if(this._fixEnabled){
				this.domNode.style.marginTop = null;
				with(tdn.style){
					position = "";
					top = "";
					zIndex = "";
					if(isIE){
						marginTop = "";
					}
				}
				if(isIE){
					dojo.html.removeClass(tdn, "IEFixedToolbar");
					dojo.html.insertBefore(tdn, this._htmlEditNode||this.domNode);
				}
				this._fixEnabled = false;
			}
		},

		unhookScroller: function(){
			this._handleScroll = false;
			clearInterval(this.scrollInterval);
			// var src = document["documentElement"]||window;
			// dojo.event.disconnect(src, "onscroll", this, "globalOnScrollHandler");
			if(dojo.render.html.ie){
				dojo.html.removeClass(this.toolbarWidget.domNode, "IEFixedToolbar");
			}
		},

		_updateToolbarLastRan: null,
		_updateToolbarTimer: null,
		_updateToolbarFrequency: 500,

		updateToolbar: function(force){
			if((!this.isLoaded)||(!this.toolbarWidget)){ return; }

			// keeps the toolbar from updating too frequently
			// TODO: generalize this functionality?
			var diff = new Date() - this._updateToolbarLastRan;
			if( (!force)&&(this._updateToolbarLastRan)&&
				((diff < this._updateToolbarFrequency)) ){

				clearTimeout(this._updateToolbarTimer);
				var _this = this;
				this._updateToolbarTimer = setTimeout(function() {
					_this.updateToolbar();
				}, this._updateToolbarFrequency/2);
				return;

			}else{
				this._updateToolbarLastRan = new Date();
			}
			// end frequency checker

			dojo.lang.forEach(this.commandList, function(cmd){
					if(cmd == "inserthtml"){ return; }
					try{
						if(this.queryCommandEnabled(cmd)){
							if(this.queryCommandState(cmd)){
								this.toolbarWidget.highlightButton(cmd);
							}else{
								this.toolbarWidget.unhighlightButton(cmd);
							}
						}
					}catch(e){
						// alert(cmd+":"+e);
					}
				}, this);

			var h = dojo.render.html;
			
			// safari f's us for selection primitives
			if(h.safari){ return; }

			var selectedNode = (h.ie) ? this.document.selection.createRange().parentElement() : this.window.getSelection().anchorNode;
			// make sure we actuall have an element
			while((selectedNode)&&(selectedNode.nodeType != 1)){
				selectedNode = selectedNode.parentNode;
			}
			if(!selectedNode){ return; }

			var formats = ["p", "pre", "h1", "h2", "h3", "h4"];
			// gotta run some specialized updates for the various
			// formatting options
			var type = formats[dojo.lang.find(formats, selectedNode.nodeName.toLowerCase())];
			while((selectedNode)&&(selectedNode!=this.editNode)&&(!type)){
				selectedNode = selectedNode.parentNode;
				type = formats[dojo.lang.find(formats, selectedNode.nodeName.toLowerCase())];
			}
			if(!type){
				type = "";
			}else{
				if(type.charAt(0)=="h"){
					this.toolbarWidget.unhighlightButton("bold");
				}
			}
			this.toolbarWidget.selectFormat(type);
		},

		updateItem: function(item) {
			try {
				var cmd = item._name;
				var enabled = this._richText.queryCommandEnabled(cmd);
				item.setEnabled(enabled, false, true);

				var active = this._richText.queryCommandState(cmd);
				if(active && cmd == "underline") {
					// don't activate underlining if we are on a link
					active = !this._richText.queryCommandEnabled("unlink");
				}
				item.setSelected(active, false, true);
				return true;
			} catch(err) {
				return false;
			}
		},


		_save: function(e){
			// FIXME: how should this behave when there's a larger form in play?
			if(!this.isClosed){
				if(this.saveUrl.length){
					var content = {};
					content[this.saveArgName] = this.getHtml();
					dojo.io.bind({
						method: this.saveMethod,
						url: this.saveUrl,
						content: content
					});
				}else{
					dojo.debug("please set a saveUrl for the editor");
				}
				if(this.closeOnSave){
					this.close(e.getName().toLowerCase() == "save");
				}
			}
		},

		wireUpOnLoad: function(){
			if(!dojo.render.html.ie){
				/*
				dojo.event.kwConnect({
					srcObj:		this.document,
					srcFunc:	"click", 
					targetObj:	this.toolbarWidget,
					targetFunc:	"hideAllDropDowns",
					once:		true
				});
				*/
			}
		}
	},
	"html",
	function(){
		var cp = dojo.widget.html.Editor2.prototype;
		if(!cp._wrappersSet){
			cp._wrappersSet = true;
			cp.fillInTemplate = (function(fit){
				return function(){
					fit.call(this);
					this.editorOnLoad();
				};
			})(cp.fillInTemplate);
		
			cp.onDisplayChanged = (function(odc){
				return function(){
					try{
						odc.call(this);
						this.updateToolbar();
					}catch(e){}
				};
			})(cp.onDisplayChanged);

			cp.onLoad = (function(ol){
				return function(){
					ol.call(this);
					this.wireUpOnLoad();
				};
			})(cp.onLoad);
		}
	}
);
