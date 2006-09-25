/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.require("dojo.widget.DomWidget");
dojo.provide("dojo.widget.SvgWidget");
dojo.provide("dojo.widget.SVGWidget"); // back compat

dojo.require("dojo.dom");

// SVGWidget is a mixin ONLY
dojo.widget.SvgWidget = function(args){
	// mix in the parent type
	// dojo.widget.DomWidget.call(this);
}
dojo.inherits(dojo.widget.SvgWidget, dojo.widget.DomWidget);

dojo.lang.extend(dojo.widget.SvgWidget, {
	getContainerHeight: function(){
		// NOTE: container height must be returned as the INNER height
		dojo.unimplemented("dojo.widget.SvgWidget.getContainerHeight");
	},

	getContainerWidth: function(){
		// return this.parent.domNode.offsetWidth;
		dojo.unimplemented("dojo.widget.SvgWidget.getContainerWidth");
	},

	setNativeHeight: function(height){
		// var ch = this.getContainerHeight();
		dojo.unimplemented("dojo.widget.SVGWidget.setNativeHeight");
	},

	createNodesFromText: function(txt, wrap){
		return dojo.dom.createNodesFromText(txt, wrap);
	}
});

dojo.widget.SVGWidget = dojo.widget.SvgWidget;

try{
(function(){
	var tf = function(){
		// FIXME: fill this in!!!
		var rw = new function(){
			dojo.widget.SvgWidget.call(this);
			this.buildRendering = function(){ return; }
			this.destroyRendering = function(){ return; }
			this.postInitialize = function(){ return; }
			this.cleanUp = function(){ return; }
			this.widgetType = "SVGRootWidget";
			this.domNode = document.documentElement;
		}
		var wm = dojo.widget.manager;
		wm.root = rw;
		wm.add(rw);

		// extend the widgetManager with a getWidgetFromNode method
		wm.getWidgetFromNode = function(node){
			var filter = function(x){
				if(x.domNode == node){
					return true;
				}
			}
			var widgets = [];
			while((node)&&(widgets.length < 1)){
				widgets = this.getWidgetsByFilter(filter);
				node = node.parentNode;
			}
			if(widgets.length > 0){
				return widgets[0];
			}else{
				return null;
			}
		}

		wm.getWidgetFromEvent = function(domEvt){
			return this.getWidgetFromNode(domEvt.target);
		}

		wm.getWidgetFromPrimitive = wm.getWidgetFromNode;
	}
	// make sure we get called when the time is right
	dojo.event.connect(dojo.hostenv, "loaded", tf);
})();
}catch(e){ alert(e); }
