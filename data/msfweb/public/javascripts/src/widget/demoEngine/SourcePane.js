/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.demoEngine.SourcePane");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.io.*");

dojo.widget.defineWidget("my.widget.demoEngine.SourcePane", 
	dojo.widget.HtmlWidget, 
	{
		templatePath: dojo.uri.dojoUri("src/widget/demoEngine/templates/SourcePane.html"),
		templateCssPath: dojo.uri.dojoUri("src/widget/demoEngine/templates/SourcePane.css"),
		postCreate: function() {
			dojo.html.addClass(this.domNode,this.domNodeClass);
			dojo.debug("PostCreate");
		},
	
		getSource: function() {
			if (this.href) {
				dojo.io.bind({
					url: this.href,
					load: dojo.lang.hitch(this, "fillInSource"),
					mimetype: "text/plain"
				});
			}
		},	

		fillInSource: function(type, source, e) {
			this.sourceNode.value=source;
		},

		setHref: function(url) {
			this.href = url;
			this.getSource();
		}
	},
	"",
	function() {
		dojo.debug("SourcePane Init");
		this.domNodeClass="sourcePane";
		this.sourceNode = "";
		this.href = "";
	}
);
