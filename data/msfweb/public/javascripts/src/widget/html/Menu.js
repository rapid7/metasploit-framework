/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.require("dojo.widget.Menu");
dojo.provide("dojo.widget.html.Menu");

/* HtmlMenu
 ***********/
 
dojo.widget.html.Menu = function(){
	dojo.widget.html.Menu.superclass.constructor.call(this);
	this.items = [];
}
dojo.inherits(dojo.widget.html.Menu, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.html.Menu, {
	widgetType: "Menu",
	isContainer: true,

	// copy children widgets output directly to parent (this node), to avoid
	// errors trying to insert an <li> under a <div>
	snarfChildDomOutput: true,

	templateString: '<ul></ul>',
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/Menu.css"),
	
	fillInTemplate: function (args, frag){
		//dojo.widget.HtmlMenu.superclass.fillInTemplate.apply(this, arguments);
		this.domNode.className = "dojoMenu";
	},
	
 
	_register: function (item ) {
		dojo.event.connect(item, "onSelect", this, "onSelect");
		this.items.push(item);
	},

	push: function (item) {
		this.domNode.appendChild(item.domNode);
		this._register(item);
	}

});

