/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.MenuItem");

/* HtmlMenuItem
 ***************/

dojo.widget.html.MenuItem = function(){
	dojo.widget.HtmlWidget.call(this);
}
dojo.inherits(dojo.widget.html.MenuItem, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.html.MenuItem, {
	widgetType: "MenuItem",
	templateString: '<li class="dojoMenuItem" dojoAttachEvent="onMouseOver; onMouseOut; onMouseDown; onMouseUp; onClick;"></li>',
	title: "",

	fillInTemplate: function(args, frag){
		dojo.html.disableSelection(this.domNode);

		if(!dojo.string.isBlank(this.title)){
			this.domNode.appendChild(document.createTextNode(this.title));
		}else{
			this.domNode.appendChild(frag["dojo:"+this.widgetType.toLowerCase()]["nodeRef"]);
		}
	},
	
	onMouseOver: function(e){
		dojo.html.addClass(this.domNode, "dojoMenuItemHover");
	},
	
	onMouseOut: function(e){
		dojo.html.removeClass(this.domNode, "dojoMenuItemHover");
	},
	
	onClick: function(e){ this.onSelect(this, e); },
	onMouseDown: function(e){},
	onMouseUp: function(e){},
	
	// By default, when I am clicked, click the item inside of me
	onSelect: function (item, e) {
		var child = dojo.dom.getFirstChildElement(this.domNode);
		if(child){
			if(child.click){
				child.click();
			}else if(child.href){
				location.href = child.href;
			}
		}
	}
});

