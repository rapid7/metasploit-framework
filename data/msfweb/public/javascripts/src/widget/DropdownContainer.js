/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.DropdownContainer");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.event.*");
dojo.require("dojo.html");

dojo.widget.defineWidget(
	"dojo.widget.DropdownContainer",
	dojo.widget.HtmlWidget,
	{
		initializer: function(){
		},

		inputWidth: "7em",
		inputId: "",
		inputName: "",
		iconURL: dojo.uri.dojoUri("src/widget/templates/images/combo_box_arrow.png"),
		iconAlt: "",

		inputNode: null,
		buttonNode: null,
		containerNode: null,
		subWidgetNode: null,

		containerToggle: "plain",
		containerToggleDuration: 150,
		containerAnimInProgress: false,

		templateString: '<div><span style="white-space:nowrap"><input type="text" value="" style="vertical-align:middle;" dojoAttachPoint="inputNode" autocomplete="off" /> <img src="${this.iconURL}" alt="${this.iconAlt}" dojoAttachPoint="buttonNode" dojoAttachEvent="onclick: onIconClick;" style="vertical-align:middle; cursor:pointer; cursor:hand;" /></span><br /><div dojoAttachPoint="containerNode" style="display:none;position:absolute;width:12em;background-color:#fff;"></div></div>',
		templateCssPath: "",

		fillInTemplate: function(args, frag){
			var source = this.getFragNodeRef(frag);
			
			this.containerNode.style.left = "";
			this.containerNode.style.top = "";

			if(this.inputId){ this.inputNode.id = this.inputId; }
			if(this.inputName){ this.inputNode.name = this.inputName; }
			this.inputNode.style.width = this.inputWidth;

			dojo.event.connect(this.inputNode, "onchange", this, "onInputChange");
			
			this.containerIframe = new dojo.html.BackgroundIframe(this.containerNode);
			this.containerIframe.size([0,0,0,0]);
		},

		postMixInProperties: function(args, frag, parentComp){
			// now that we know the setting for toggle, get toggle object
			// (default to plain toggler if user specified toggler not present)
			this.containerToggleObj =
				dojo.lfx.toggle[this.containerToggle.toLowerCase()] || dojo.lfx.toggle.plain;
			dojo.widget.DropdownContainer.superclass.postMixInProperties.call(this, args, frag, parentComp);
		},

		onIconClick: function(evt){
			this.toggleContainerShow();
		},

		toggleContainerShow: function(){
			if(dojo.html.isShowing(this.containerNode)){
				this.hideContainer();
			}else{
				this.showContainer();
			}
		},
		
		showContainer: function(){
			this.containerAnimInProgress=true;
			this.containerToggleObj.show(this.containerNode, this.containerToggleDuration, null,
				dojo.lang.hitch(this, this.onContainerShow), this.explodeSrc);
			dojo.lang.setTimeout(this, this.sizeBackgroundIframe, this.containerToggleDuration);
		},

		onContainerShow: function(){
			this.containerAnimInProgress=false;
		},

		hideContainer: function(){
			this.containerAnimInProgress=true;
			this.containerToggleObj.hide(this.containerNode, this.containerToggleDuration, null,
				dojo.lang.hitch(this, this.onContainerHide), this.explodeSrc);
			dojo.lang.setTimeout(this, this.sizeBackgroundIframe, this.containerToggleDuration);
		},

		onContainerHide: function(){
			this.containerAnimInProgress=false;
		},
		
		sizeBackgroundIframe: function(){
			var w = dojo.style.getOuterWidth(this.containerNode);
			var h = dojo.style.getOuterHeight(this.containerNode);
			if(w==0||h==0){
				// need more time to calculate size
				dojo.lang.setTimeout(this, "sizeBackgroundIframe", 100);
				return;
			}
			if(dojo.html.isShowing(this.containerNode)){
				this.containerIframe.size([0,0,w,h]);
			}
		},

		onInputChange: function(){}
	},
	"html"
);

dojo.widget.tags.addParseTreeHandler("dojo:dropdowncontainer");
