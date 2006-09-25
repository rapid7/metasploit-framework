/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.ResizableTextarea");
dojo.require("dojo.html");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.LayoutContainer");
dojo.require("dojo.widget.ResizeHandle");

dojo.widget.tags.addParseTreeHandler("dojo:resizabletextarea");

dojo.widget.ResizableTextarea = function(){
	dojo.widget.HtmlWidget.call(this);
}

dojo.inherits(dojo.widget.ResizableTextarea, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.ResizableTextarea, {
	templatePath: dojo.uri.dojoUri("src/widget/templates/HtmlResizableTextarea.html"),
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlResizableTextarea.css"),
	widgetType: "ResizableTextarea",
	tagName: "dojo:resizabletextarea",
	isContainer: false,
	textAreaNode: null,
	textAreaContainer: null,
	textAreaContainerNode: null,
	statusBar: null,
	statusBarContainerNode: null,
	statusLabelNode: null,
	statusLabel: null,
	rootLayoutNode: null,
	resizeHandleNode: null,
	resizeHandle: null,

	fillInTemplate: function(args, frag){
		this.textAreaNode = this.getFragNodeRef(frag).cloneNode(true);

		// FIXME: Safari apparently needs this!
		document.body.appendChild(this.domNode);

		this.rootLayout = dojo.widget.createWidget(
			"LayoutContainer",
			{
				minHeight: 50,
				minWidth: 100
			},
			this.rootLayoutNode
		);


		this.textAreaContainer = dojo.widget.createWidget(
			"LayoutContainer",
			{ layoutAlign: "client" },
			this.textAreaContainerNode
		);
		this.rootLayout.addChild(this.textAreaContainer);

		this.textAreaContainer.domNode.appendChild(this.textAreaNode);
		with(this.textAreaNode.style){
			width="100%";
			height="100%";
		}

		this.statusBar = dojo.widget.createWidget(
			"LayoutContainer",
			{ 
				layoutAlign: "bottom", 
				minHeight: 28
			},
			this.statusBarContainerNode
		);
		this.rootLayout.addChild(this.statusBar);

		this.statusLabel = dojo.widget.createWidget(
			"LayoutContainer",
			{ 
				layoutAlign: "client", 
				minWidth: 50
			},
			this.statusLabelNode
		);
		this.statusBar.addChild(this.statusLabel);

		this.resizeHandle = dojo.widget.createWidget(
			"ResizeHandle", 
			{ targetElmId: this.rootLayout.widgetId },
			this.resizeHandleNode
		);
		this.statusBar.addChild(this.resizeHandle);
		// dojo.debug(this.rootLayout.widgetId);

		// dojo.event.connect(this.resizeHandle, "beginSizing", this, "hideContent");
		// dojo.event.connect(this.resizeHandle, "endSizing", this, "showContent");
	},

	hideContent: function(){
		this.textAreaNode.style.display = "none";
	},

	showContent: function(){
		this.textAreaNode.style.display = "";
	}
});
