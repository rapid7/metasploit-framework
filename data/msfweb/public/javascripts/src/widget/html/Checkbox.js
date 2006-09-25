/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.Checkbox");

dojo.require("dojo.widget.*");
dojo.require("dojo.event");
dojo.require("dojo.html");

dojo.widget.defineWidget(
	"dojo.widget.html.Checkbox",
	dojo.widget.HtmlWidget,
	{
		widgetType: "Checkbox",
	
		templatePath: dojo.uri.dojoUri('src/widget/templates/HtmlCheckBox.html'),

		srcOn: dojo.uri.dojoUri('src/widget/templates/check_on.gif'),
		srcOff: dojo.uri.dojoUri('src/widget/templates/check_off.gif'),
		srcDisabledOn: dojo.uri.dojoUri('src/widget/templates/check_disabled_on.gif'),
		srcDisabledOff: dojo.uri.dojoUri('src/widget/templates/check_disabled_off.gif'),
		srcHoverOn: dojo.uri.dojoUri('src/widget/templates/check_hover_on.gif'),
		srcHoverOff: dojo.uri.dojoUri('src/widget/templates/check_hover_off.gif'),

		imgSrc: null,

		// parameters
		disabled: "enabled",
		name: "",
		checked: false,
		tabIndex: -1,

		imgNode: null,
		inputNode: null,

		postMixInProperties: function(){
			// set correct source for image before instantiating template
			this._updateImgSrc();
		},

		onMouseUp: function(){
			if(this.disabled == "enabled"){
				this.checked = !this.checked;
				this.inputNode.checked = this.checked;
				this._updateImgSrc();
			}
		},

		onMouseOver: function(){
			this.hover=true;
			this._updateImgSrc();
		},

		onMouseOut: function(){
			this.hover=false;
			this._updateImgSrc();
		},

		_updateImgSrc: function(){
			if(this.disabled == "enabled"){
				if(this.hover){
					this.imgSrc = this.checked ? this.srcHoverOn : this.srcHoverOff;
				}else{
					this.imgSrc = this.checked ? this.srcOn : this.srcOff;
				}
			}else{
				this.imgSrc = this.checked ? this.srcDisabledOn : this.srcDisabledOff;
			}
			if(this.imgNode){
				this.imgNode.src = this.imgSrc;
			}
		}
	}
);

