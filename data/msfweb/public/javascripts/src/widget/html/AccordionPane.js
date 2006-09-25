/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.AccordionPane");
dojo.require("dojo.widget.TitlePane");

dojo.widget.html.AccordionPane = function(){

	dojo.widget.html.TitlePane.call(this);
	this.widgetType = "AccordionPane";

	this.open=false;
	this.allowCollapse=true;
	this.label="";
	this.open=false;

	this.labelNodeClass="";
	this.containerNodeClass="";
}

dojo.inherits(dojo.widget.html.AccordionPane, dojo.widget.html.TitlePane);

dojo.lang.extend(dojo.widget.html.AccordionPane, {
        postCreate: function() {
                dojo.widget.html.AccordionPane.superclass.postCreate.call(this);
		this.domNode.widgetType=this.widgetType;
		this.setSizes();
		dojo.html.addClass(this.labelNode, this.labelNodeClass);
		dojo.html.disableSelection(this.labelNode);
		dojo.html.addClass(this.containerNode, this.containerNodeClass);
        },

	collapse: function() {
		//dojo.fx.html.wipeOut(this.containerNode,250);
		//var anim = dojo.fx.html.wipe(this.containerNode, 1000, this.containerNode.offsetHeight, 0, null, true);
		this.containerNode.style.display="none";
		this.open=false;
	},

	expand: function() {
		//dojo.fx.html.wipeIn(this.containerNode,250);
		this.containerNode.style.display="block";
		//var anim = dojo.fx.html.wipe(this.containerNode, 1000, 0, this.containerNode.scrollHeight, null, true);
		this.open=true;
	},

	getCollapsedHeight: function() {
		return dojo.style.getOuterHeight(this.labelNode)+1;
	},

	setSizes: function() {
		var siblings = this.domNode.parentNode.childNodes;
		var height=dojo.style.getInnerHeight(this.domNode.parentNode)-this.getCollapsedHeight();

		this.siblingWidgets = [];
	
		for (var x=0; x<siblings.length; x++) {
			if (siblings[x].widgetType==this.widgetType) {
				if (this.domNode != siblings[x]) {
					var ap = dojo.widget.byNode(siblings[x]);
					this.siblingWidgets.push(ap);
					height -= ap.getCollapsedHeight();
				}
			}
		}
	
		for (var x=0; x<this.siblingWidgets.length; x++) {
			dojo.style.setOuterHeight(this.siblingWidgets[x].containerNode,height);
		}

		dojo.style.setOuterHeight(this.containerNode,height);
	},

	onLabelClick: function() {
		this.setSizes();
		if (!this.open) { 
			for (var x=0; x<this.siblingWidgets.length;x++) {
				if (this.siblingWidgets[x].open) {
					this.siblingWidgets[x].collapse();
				}
			}
			this.expand();
		} else {
			if (this.allowCollapse) {
				this.collapse();
			}
		}
	}
});

dojo.widget.tags.addParseTreeHandler("dojo:AccordionPane");
