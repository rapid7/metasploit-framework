/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.Editor2Toolbar");
dojo.provide("dojo.widget.html.Editor2Toolbar");

dojo.require("dojo.lang.*");
dojo.require("dojo.widget.*");
dojo.require("dojo.event.*");
dojo.require("dojo.widget.RichText");
dojo.require("dojo.widget.ColorPalette");

dojo.widget.defineWidget(
	"dojo.widget.html.Editor2Toolbar",
	dojo.widget.HtmlWidget,
	{
		commandList: [ "bold", "italic", "underline", "subscript", "superscript",
			"fontname", "fontsize", "forecolor", "hilitecolor", "justifycenter",
			"justifyfull", "justifyleft", "justifyright", "cut", "copy", "paste",
			"delete", "undo", "redo", "createlink", "unlink", "removeformat",
			"inserthorizontalrule", "insertimage", "insertorderedlist",
			"insertunorderedlist", "indent", "outdent", "formatblock", "strikethrough", 
			"inserthtml", "blockdirltr", "blockdirrtl", "dirltr", "dirrtl",
			"inlinedirltr", "inlinedirrtl", "inserttable", "insertcell",
			"insertcol", "insertrow", "deletecells", "deletecols", "deleterows",
			"mergecells", "splitcell"
		],

		templatePath: dojo.uri.dojoUri("src/widget/templates/HtmlEditorToolbar.html"),
		templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlEditorToolbar.css"),

		forecolorPalette: null,
		hilitecolorPalette: null,

		// DOM Nodes
		wikiwordButton: null,
		htmltoggleButton: null,
		insertimageButton: null,
		styleDropdownButton: null,
		styleDropdownContainer: null,
		copyButton: null,
		boldButton: null,
		italicButton: null,
		underlineButton: null,
		justifycenterButton: null,
		justifyleftButton: null,
		justifyfullButton: null,
		justifyrightButton: null,
		pasteButton: null,
		undoButton: null,
		redoButton: null,
		linkButton: null,
		insertunorderedlistButton: null,
		insertorderedlistButton: null,
		forecolorButton: null,
		forecolorDropDown: null,
		hilitecolorButton: null,
		hilitecolorDropDown: null,
		formatSelectBox: null,
		inserthorizontalruleButton: null,
		strikethroughButton: null,
		clickInterceptDiv: null,
		oneLineTr: null,

		buttonClick: function(e){ e.preventDefault(); /* dojo.debug("buttonClick"); */ },

		buttonMouseOver: function(e){  },
		buttonMouseOut: function(e){  },


		// event signals
		preventSelect: function(e){ if(dojo.render.html.safari){ e.preventDefault(); } },
		wikiwordClick: function(){ },
		insertimageClick: function(){ },
		htmltoggleClick: function(){ },

		styleDropdownClick: function(){
			dojo.debug("styleDropdownClick:", this.styleDropdownContainer);
			dojo.style.toggleShowing(this.styleDropdownContainer);
		},


		copyClick: function(){ this.exec("copy"); },
		boldClick: function(){ this.exec("bold"); },
		italicClick: function(){ this.exec("italic"); },
		underlineClick: function(){ this.exec("underline"); },
		justifyleftClick: function(){ this.exec("justifyleft"); },
		justifycenterClick: function(){ this.exec("justifycenter"); },
		justifyfullClick: function(){ this.exec("justifyfull"); },
		justifyrightClick: function(){ this.exec("justifyright"); },
		pasteClick: function(){ this.exec("paste"); },
		undoClick: function(){ this.exec("undo"); },
		redoClick: function(){ this.exec("redo"); },
		linkClick: function(){ 
			// FIXME: we need to alert the user if they haven't selected any text
			// this.exec(	"createlink", 
			// 			prompt("Please enter the URL of the link:", "http://"));
		},
		insertunorderedlistClick: function(){ this.exec("insertunorderedlist"); },
		insertorderedlistClick: function(){ this.exec("insertorderedlist"); },
		inserthorizontalruleClick: function(){ this.exec("inserthorizontalrule"); },
		strikethroughClick: function(){ this.exec("strikethrough"); },

		formatSelectClick: function(){ 
			var sv = this.formatSelectBox.value.toLowerCase();
			this.exec("formatblock", sv);
		},

		normalTextClick: function(){ this.exec("formatblock", "p"); },
		h1TextClick: function(){ this.exec("formatblock", "h1"); },
		h2TextClick: function(){ this.exec("formatblock", "h2"); },
		h3TextClick: function(){ this.exec("formatblock", "h3"); },
		h4TextClick: function(){ this.exec("formatblock", "h4"); },
		indentClick: function(){ this.exec("indent"); },
		outdentClick: function(){ this.exec("outdent"); },


		hideAllDropDowns: function(){
			this.domNode.style.height = "";
			dojo.lang.forEach(dojo.widget.byType("Editor2Toolbar"), function(tb){
				try{
					dojo.style.hide(tb.forecolorDropDown);
					dojo.style.hide(tb.hilitecolorDropDown);
					dojo.style.hide(tb.styleDropdownContainer);
					if(tb.clickInterceptDiv){
						dojo.style.hide(tb.clickInterceptDiv);
					}
				}catch(e){}
				if(dojo.render.html.ie){
					try{
						dojo.style.hide(tb.forecolorPalette.bgIframe);
					}catch(e){}
					try{
						dojo.style.hide(tb.hilitecolorPalette.bgIframe);
					}catch(e){}
				}
			});
		},

		selectFormat: function(format){
			dojo.lang.forEach(this.formatSelectBox.options, function(item){
				if(item.value.toLowerCase() == format.toLowerCase()){
					item.selected = true;
				}
			});
		},

		forecolorClick: function(e){
			this.colorClick(e, "forecolor");
		},

		hilitecolorClick: function(e){
			this.colorClick(e, "hilitecolor");
		},

		// FIXME: these methods aren't currently dealing with clicking in the
		// general document to hide the menu
		colorClick: function(e, type){
			var h = dojo.render.html;
			this.hideAllDropDowns();
			// FIXME: if we've been "popped out", we need to set the height of the toolbar.
			e.stopPropagation();
			var dd = this[type+"DropDown"];
			var pal = this[type+"Palette"];
			dojo.style.toggleShowing(dd);
			if(!pal){
				pal = this[type+"Palette"] = dojo.widget.createWidget("ColorPalette", {}, dd, "first");
				var fcp = pal.domNode;
				with(dd.style){
					width = dojo.html.getOuterWidth(fcp) + "px";
					height = dojo.html.getOuterHeight(fcp) + "px";
					zIndex = 1002;
					position = "absolute";
				}

				dojo.event.connect(	"after",
									pal, "onColorSelect",
									this, "exec",
									function(mi){ mi.args.unshift(type); return mi.proceed(); }
				);

				dojo.event.connect(	"after",
									pal, "onColorSelect",
									dojo.style, "toggleShowing",
									this, function(mi){ mi.args.unshift(dd); return mi.proceed(); }
				);

				var cid = this.clickInterceptDiv;
				if(!cid){
					cid = this.clickInterceptDiv = document.createElement("div");
					document.body.appendChild(cid);
					with(cid.style){
						backgroundColor = "transparent";
						top = left = "0px";
						height = width = "100%";
						position = "absolute";
						border = "none";
						display = "none";
						zIndex = 1001;
					}
					dojo.event.connect(cid, "onclick", function(){ cid.style.display = "none"; });
				}
				dojo.event.connect(pal, "onColorSelect", function(){ cid.style.display = "none"; });

				dojo.event.kwConnect({
					srcObj:		document.body, 
					srcFunc:	"onclick", 
					targetObj:	this,
					targetFunc:	"hideAllDropDowns",
					once:		true
				});
				document.body.appendChild(dd);
			}
			dojo.style.toggleShowing(this.clickInterceptDiv);
			var pos = dojo.style.abs(this[type+"Button"]);
			dojo.html.placeOnScreenPoint(dd, pos.x, pos.y, 0, false);
			if(pal.bgIframe){
				with(pal.bgIframe.style){
					display = "block";
					left = dd.style.left;
					top = dd.style.top;
					width = dojo.style.getOuterWidth(dd)+"px";
					height = dojo.style.getOuterHeight(dd)+"px";
				}
			}
		},

		uninitialize: function(){
			if(!dojo.render.html.ie){
				// apparently this causes leakage on IE!
				dojo.event.kwDisconnect({
					srcObj:		document.body, 
					srcFunc:	"onclick", 
					targetObj:	this,
					targetFunc:	"hideAllDropDowns",
					once:		true
				});
			}
		},

		// stub for observers
		exec: function(what, arg){ /* dojo.debug(what, new Date()); */ },

		hideUnusableButtons: function(obj){
			var op = obj||dojo.widget.html.RichText.prototype;
			dojo.lang.forEach(this.commandList,
				function(cmd){
					if(this[cmd+"Button"]){
						var cb = this[cmd+"Button"];
						if(!op.queryCommandAvailable(cmd)){
							cb.style.display = "none";
							cb.parentNode.style.display = "none";
						}
					}
				},
				this);
				if(this.oneLineTr){
					var lastVisibleIsSpacer = false;
					var lastVisible = false;
					var tds = this.oneLineTr.getElementsByTagName("td");
					dojo.lang.forEach(tds, function(td){
						if(td.getAttribute("isSpacer")){
							if(td.style.display != "none"){
								if(lastVisibleIsSpacer){
									td.style.display = "none";
								}
								lastVisibleIsSpacer = true;
							}else{
								lastVisible = td;
								lastVisibleIsSpacer = true;
							}
						}else{
							if(td.style.display != "none"){
								lastVisible = td;
								lastVisibleIsSpacer = false;
							}
						}
					});
				}
		},

		highlightButton: function(name){
			var bn = name+"Button";
			if(this[bn]){
				with(this[bn].style){
					backgroundColor = "White";
					border = "1px solid #aeaeab";
				}
			}
		},

		unhighlightButton: function(name){
			var bn = name+"Button";
			if(this[bn]){
				// dojo.debug("unhighlighting:", name);
				with(this[bn].style){
					backgroundColor = "";
					border = "";
				}
			}
		}
	},
	"html",
	function(){
		// dojo.event.connect(this, "fillInTemplate", this, "hideUnusableButtons");
		dojo.event.connect(this, "fillInTemplate", dojo.lang.hitch(this, function(){
			if(dojo.render.html.ie){
				this.domNode.style.zoom = 1.0;
			}
		}));
	}
);
