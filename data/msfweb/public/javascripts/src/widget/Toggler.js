/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.Toggler");
dojo.require("dojo.widget.*");
dojo.require("dojo.event.*");

// clicking on this node shows/hides another widget

dojo.widget.Toggler = function(){
	dojo.widget.DomWidget.call(this);
}

dojo.inherits(dojo.widget.Toggler, dojo.widget.DomWidget);

dojo.lang.extend(dojo.widget.Toggler, {
	widgetType: "Toggler",
	
	// Associated widget 
	targetId: '',
	
	fillInTemplate: function() {
		dojo.event.connect(this.domNode, "onclick", this, "onClick");
	},
	
	onClick: function() {
		var pane = dojo.widget.byId(this.targetId);
		if(!pane){ return; }
		pane.explodeSrc = this.domNode;
		pane.toggleShowing();
	}
});
dojo.widget.tags.addParseTreeHandler("dojo:toggler");
