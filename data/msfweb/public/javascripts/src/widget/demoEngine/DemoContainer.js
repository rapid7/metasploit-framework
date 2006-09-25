/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.demoEngine.DemoContainer");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.widget.demoEngine.DemoPane");
dojo.require("dojo.widget.demoEngine.SourcePane");
dojo.require("dojo.widget.TabContainer");

dojo.widget.defineWidget("my.widget.demoEngine.DemoContainer", 
	dojo.widget.HtmlWidget, 
	{
		templatePath: dojo.uri.dojoUri("src/widget/demoEngine/templates/DemoContainer.html"),
		templateCssPath: dojo.uri.dojoUri("src/widget/demoEngine/templates/DemoContainer.css"),
		postCreate: function() {
			dojo.html.addClass(this.domNode,this.domNodeClass);
			dojo.html.addClass(this.tabNode, this.tabClass);
			dojo.html.addClass(this.returnImageNode, this.returnClass);
			this.returnImageNode.src=this.returnImage;

			this.tabContainer = dojo.widget.createWidget("TabContainer",{},this.tabNode);

			this.demoTab = dojo.widget.createWidget("DemoPane",{});
			this.tabContainer.addChild(this.demoTab);

			this.sourceTab= dojo.widget.createWidget("SourcePane",{});
			this.tabContainer.addChild(this.sourceTab);

			dojo.html.setOpacity(this.domNode,0);
			dojo.html.hide(this.domNode);
		},

		loadDemo: function(url) {
			this.demoTab.setHref(url);
			this.sourceTab.setHref(url);
			this.showDemo();
		},

		setName: function(name) {
			dojo.html.removeChildren(this.demoNameNode);
			this.demoNameNode.appendChild(document.createTextNode(name));
		},

		setSummary: function(summary) {
			dojo.html.removeChildren(this.summaryNode);
			this.summaryNode.appendChild(document.createTextNode(summary));
		},

		showSource: function() {
			dojo.html.removeClass(this.demoButtonNode,this.selectedButtonClass);
			dojo.html.addClass(this.sourceButtonNode,this.selectedButtonClass);
			this.tabContainer.selectTab(this.sourceTab);	
		},

		showDemo: function() {
			dojo.html.removeClass(this.sourceButtonNode,this.selectedButtonClass);
			dojo.html.addClass(this.demoButtonNode,this.selectedButtonClass);
			this.tabContainer.selectTab(this.demoTab);
		},

		returnToDemos: function() {
			dojo.debug("Return To Demos");
		},

		show: function() {
			dojo.html.setOpacity(this.domNode,1);
			dojo.html.show(this.domNode);
			this.tabContainer.checkSize();
		}
	},
	"",
	function() {
		dojo.debug("DemoPane Init");
		this.domNodeClass="demoContainer";

		this.tabContainer="";
		this.sourceTab="";
		this.demoTab="";

		this.headerNode="";
		this.returnNode="";
	
		this.returnImageNode="";
		this.returnImage="images/dojoDemos.gif";
		this.returnClass="return";
		
		this.summaryNode="";
		this.demoNameNode="";
		this.tabControlNode="";

		this.tabNode="";
		this.tabClass = "demoContainerTabs";

		this.sourceButtonNode="";
		this.demoButtonNode="";

		this.selectedButtonClass="selected";
	}
);
