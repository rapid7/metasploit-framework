/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/* TODO:
 * - font selector
 * - test, bug fix, more features :)
*/
dojo.provide("dojo.widget.Editor");
dojo.provide("dojo.widget.html.Editor");
dojo.require("dojo.io.*");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.Toolbar");
dojo.require("dojo.widget.RichText");
dojo.require("dojo.widget.ColorPalette");
dojo.require("dojo.string.extras");

dojo.widget.tags.addParseTreeHandler("dojo:Editor");

dojo.widget.html.Editor = function() {
	dojo.widget.HtmlWidget.call(this);
	this.contentFilters = [];
	this._toolbars = [];
}
dojo.inherits(dojo.widget.html.Editor, dojo.widget.HtmlWidget);

dojo.widget.html.Editor.itemGroups = {
	textGroup: ["bold", "italic", "underline", "strikethrough"],
	blockGroup: ["formatBlock", "fontName", "fontSize"],
	justifyGroup: ["justifyleft", "justifycenter", "justifyright"],
	commandGroup: ["save", "cancel"],
	colorGroup: ["forecolor", "hilitecolor"],
	listGroup: ["insertorderedlist", "insertunorderedlist"],
	indentGroup: ["outdent", "indent"],
	linkGroup: ["createlink", "insertimage", "inserthorizontalrule"]
};

dojo.widget.html.Editor.formatBlockValues = {
	"Normal": "p",
	"Main heading": "h2",
	"Sub heading": "h3",
	"Sub sub heading": "h4",
	"Preformatted": "pre"
};

dojo.widget.html.Editor.fontNameValues = {
	"Arial": "Arial, Helvetica, sans-serif",
	"Verdana": "Verdana, sans-serif",
	"Times New Roman": "Times New Roman, serif",
	"Courier": "Courier New, monospace"
};

dojo.widget.html.Editor.fontSizeValues = {
	"1 (8 pt)" : "1",
	"2 (10 pt)": "2",
	"3 (12 pt)": "3",
	"4 (14 pt)": "4",
	"5 (18 pt)": "5",
	"6 (24 pt)": "6",
	"7 (36 pt)": "7"
};

dojo.widget.html.Editor.defaultItems = [
	"commandGroup", "|", "blockGroup", "|", "textGroup", "|", "colorGroup", "|", "justifyGroup", "|", "listGroup", "indentGroup", "|", "linkGroup"
];

// ones we support by default without asking the RichText component
// NOTE: you shouldn't put buttons like bold, italic, etc in here
dojo.widget.html.Editor.supportedCommands = ["save", "cancel", "|", "-", "/", " "];

dojo.lang.extend(dojo.widget.html.Editor, {
	widgetType: "Editor",

	saveUrl: "",
	saveMethod: "post",
	saveArgName: "editorContent",
	closeOnSave: false,
	items: dojo.widget.html.Editor.defaultItems,
	formatBlockItems: dojo.lang.shallowCopy(dojo.widget.html.Editor.formatBlockValues),
	fontNameItems: dojo.lang.shallowCopy(dojo.widget.html.Editor.fontNameValues),
	fontSizeItems: dojo.lang.shallowCopy(dojo.widget.html.Editor.fontSizeValues),

	// used to get the properties of an item if it is given as a string
	getItemProperties: function(name) {
		var props = {};
		switch(name.toLowerCase()) {
			case "bold":
			case "italic":
			case "underline":
			case "strikethrough":
				props.toggleItem = true;
				break;

			case "justifygroup":
				props.defaultButton = "justifyleft";
				props.preventDeselect = true;
				props.buttonGroup = true;
				break;

			case "listgroup":
				props.buttonGroup = true;
				break;

			case "save":
			case "cancel":
				props.label = dojo.string.capitalize(name);
				break;

			case "forecolor":
			case "hilitecolor":
				props.name = name;
				props.toggleItem = true; // FIXME: they aren't exactly toggle items
				props.icon = this.getCommandImage(name);
				break;

			case "formatblock":
				props.name = "formatBlock";
				props.values = this.formatBlockItems;
				break;

			case "fontname":
				props.name = "fontName";
				props.values = this.fontNameItems;

			case "fontsize":
				props.name = "fontSize";
				props.values = this.fontSizeItems;
		}
		return props;
	},

	validateItems: true, // set to false to add items, regardless of support
	focusOnLoad: true,
	minHeight: "1em",

	_richText: null, // RichText widget
	_richTextType: "RichText",

	_toolbarContainer: null, // ToolbarContainer widget
	_toolbarContainerType: "ToolbarContainer",

	_toolbars: [],
	_toolbarType: "Toolbar",

	_toolbarItemType: "ToolbarItem",

	buildRendering: function(args, frag) {
		// get the node from args/frag
		var node = frag["dojo:"+this.widgetType.toLowerCase()]["nodeRef"];
		var trt = dojo.widget.createWidget(this._richTextType, {
			focusOnLoad: this.focusOnLoad,
			minHeight: this.minHeight
		}, node)
		var _this = this;
		// this appears to fix a weird timing bug on Safari
		setTimeout(function(){
			_this.setRichText(trt);

			_this.initToolbar();

			_this.fillInTemplate(args, frag);
		}, 0);
	},

	setRichText: function(richText) {
		if(this._richText && this._richText == richText) {
			dojo.debug("Already set the richText to this richText!");
			return;
		}

		if(this._richText && !this._richText.isClosed) {
			dojo.debug("You are switching richTexts yet you haven't closed the current one. Losing reference!");
		}
		this._richText = richText;
		dojo.event.connect(this._richText, "close", this, "onClose");
		dojo.event.connect(this._richText, "onLoad", this, "onLoad");
		dojo.event.connect(this._richText, "onDisplayChanged", this, "updateToolbar");
		if(this._toolbarContainer) {
			this._toolbarContainer.enable();
			this.updateToolbar(true);
		}
	},

	initToolbar: function() {
		// var tic = new Date();
		if(this._toolbarContainer) { return; } // only create it once
		this._toolbarContainer = dojo.widget.createWidget(this._toolbarContainerType);
		var tb = this.addToolbar();
		var last = true;
		for(var i = 0; i < this.items.length; i++) {
			if(this.items[i] == "\n") { // new row
				tb = this.addToolbar();
			} else {
				if((this.items[i] == "|")&&(!last)){
					last = true;
				}else{
					last = this.addItem(this.items[i], tb);
				}
			}
		}
		this.insertToolbar(this._toolbarContainer.domNode, this._richText.domNode);
		// alert(new Date - tic);
	},

	// allow people to override this so they can make their own placement logic
	insertToolbar: function(tbNode, richTextNode) {
		dojo.html.insertBefore(tbNode, richTextNode);
		//dojo.html.insertBefore(this._toolbarContainer.domNode, this._richText.domNode);
	},

	addToolbar: function(toolbar) {
		this.initToolbar();
		if(!(toolbar instanceof dojo.widget.html.Toolbar)) {
			toolbar = dojo.widget.createWidget(this._toolbarType);
		}
		this._toolbarContainer.addChild(toolbar);
		this._toolbars.push(toolbar);
		return toolbar;
	},

	addItem: function(item, tb, dontValidate) {
		if(!tb) { tb = this._toolbars[0]; }
		var cmd = ((item)&&(!dojo.lang.isUndefined(item["getValue"]))) ?  cmd = item["getValue"](): item;

		var groups = dojo.widget.html.Editor.itemGroups;
		if(item instanceof dojo.widget.ToolbarItem) {
			tb.addChild(item);
		} else if(groups[cmd]) {
			var group = groups[cmd];
			var worked = true;
			if(cmd == "justifyGroup" || cmd == "listGroup") {
				var btnGroup = [cmd];
				for(var i = 0 ; i < group.length; i++) {
					if(dontValidate || this.isSupportedCommand(group[i])) {
						btnGroup.push(this.getCommandImage(group[i]));
					}else{
						worked = false;
					}
				}
				if(btnGroup.length){
					/*
					// the addChild interface is assinine. Work around it.
					var tprops = this.getItemProperties(cmd);
					var tmpGroup = dojo.widget.createWidget("ToolbarButtonGroup", tprops);
					dojo.debug(btnGroup);
					dojo.event.connect(tmpGroup, "onClick", this, "_action");
					dojo.event.connect(tmpGroup, "onChangeSelect", this, "_action");
					*/
					var btn = tb.addChild(btnGroup, null, this.getItemProperties(cmd));
					dojo.event.connect(btn, "onClick", this, "_action");
					dojo.event.connect(btn, "onChangeSelect", this, "_action");
				}
				return worked;
			} else {
				for(var i = 0; i < group.length; i++) {
					if(!this.addItem(group[i], tb)){
						worked = false;
					}
				}
				return worked;
			}
		} else {
			if((!dontValidate)&&(!this.isSupportedCommand(cmd))){
				return false;
			}
			if(dontValidate || this.isSupportedCommand(cmd)) {
				cmd = cmd.toLowerCase();
				if(cmd == "formatblock") {
					var select = dojo.widget.createWidget("ToolbarSelect", {
						name: "formatBlock",
						values: this.formatBlockItems
					});
					tb.addChild(select);
					var _this = this;
					dojo.event.connect(select, "onSetValue", function(item, value) {
						_this.onAction("formatBlock", value);
					});
				} else if(cmd == "fontname") {
					var select = dojo.widget.createWidget("ToolbarSelect", {
						name: "fontName",
						values: this.fontNameItems
					});
					tb.addChild(select);
					dojo.event.connect(select, "onSetValue", dojo.lang.hitch(this, function(item, value) {
						this.onAction("fontName", value);
					}));
				} else if(cmd == "fontsize") {
					var select = dojo.widget.createWidget("ToolbarSelect", {
						name: "fontSize",
						values: this.fontSizeItems
					});
					tb.addChild(select);
					dojo.event.connect(select, "onSetValue", dojo.lang.hitch(this, function(item, value) {
						this.onAction("fontSize", value);
					}));
				} else if(dojo.lang.inArray(cmd, ["forecolor", "hilitecolor"])) {
					var btn = tb.addChild(dojo.widget.createWidget("ToolbarColorDialog", this.getItemProperties(cmd)));
					dojo.event.connect(btn, "onSetValue", this, "_setValue");
				} else {
					var btn = tb.addChild(this.getCommandImage(cmd), null, this.getItemProperties(cmd));
					if(cmd == "save"){
						dojo.event.connect(btn, "onClick", this, "_save");
					}else if(cmd == "cancel"){
						dojo.event.connect(btn, "onClick", this, "_close");
					} else {
						dojo.event.connect(btn, "onClick", this, "_action");
						dojo.event.connect(btn, "onChangeSelect", this, "_action");
					}
				}
			}
		}
		return true;
	},

	enableToolbar: function() {
		if(this._toolbarContainer) {
			this._toolbarContainer.domNode.style.display = "";
			this._toolbarContainer.enable();
		}
	},

	disableToolbar: function(hide){
		if(hide){
			if(this._toolbarContainer){
				this._toolbarContainer.domNode.style.display = "none";
			}
		}else{
			if(this._toolbarContainer){
				this._toolbarContainer.disable();
			}
		}
	},

	_updateToolbarLastRan: null,
	_updateToolbarTimer: null,
	_updateToolbarFrequency: 500,

	updateToolbar: function(force) {
		if(!this._toolbarContainer) { return; }

		// keeps the toolbar from updating too frequently
		// TODO: generalize this functionality?
		var diff = new Date() - this._updateToolbarLastRan;
		if(!force && this._updateToolbarLastRan && (diff < this._updateToolbarFrequency)) {
			clearTimeout(this._updateToolbarTimer);
			var _this = this;
			this._updateToolbarTimer = setTimeout(function() {
				_this.updateToolbar();
			}, this._updateToolbarFrequency/2);
			return;
		} else {
			this._updateToolbarLastRan = new Date();
		}
		// end frequency checker

		var items = this._toolbarContainer.getItems();
		for(var i = 0; i < items.length; i++) {
			var item = items[i];
			if(item instanceof dojo.widget.html.ToolbarSeparator) { continue; }
			var cmd = item._name;
			if (cmd == "save" || cmd == "cancel") { continue; }
			else if(cmd == "justifyGroup") {
				try {
					if(!this._richText.queryCommandEnabled("justifyleft")) {
						item.disable(false, true);
					} else {
						item.enable(false, true);
						var jitems = item.getItems();
						for(var j = 0; j < jitems.length; j++) {
							var name = jitems[j]._name;
							var value = this._richText.queryCommandValue(name);
							if(typeof value == "boolean" && value) {
								value = name;
								break;
							} else if(typeof value == "string") {
								value = "justify"+value;
							} else {
								value = null;
							}
						}
						if(!value) { value = "justifyleft"; } // TODO: query actual style
						item.setValue(value, false, true);
					}
				} catch(err) {}
			} else if(cmd == "listGroup") {
				var litems = item.getItems();
				for(var j = 0; j < litems.length; j++) {
					this.updateItem(litems[j]);
				}
			} else {
				this.updateItem(item);
			}
		}
	},

	updateItem: function(item) {
		try {
			var cmd = item._name;
			var enabled = this._richText.queryCommandEnabled(cmd);
			item.setEnabled(enabled, false, true);

			var active = this._richText.queryCommandState(cmd);
			if(active && cmd == "underline") {
				// don't activate underlining if we are on a link
				active = !this._richText.queryCommandEnabled("unlink");
			}
			item.setSelected(active, false, true);
			return true;
		} catch(err) {
			return false;
		}
	},

	supportedCommands: dojo.widget.html.Editor.supportedCommands.concat(),

	isSupportedCommand: function(cmd) {
		// FIXME: how do we check for ActiveX?
		var yes = dojo.lang.inArray(cmd, this.supportedCommands);
		if(!yes) {
			try {
				var richText = this._richText || dojo.widget.HtmlRichText.prototype;
				yes = richText.queryCommandAvailable(cmd);
			} catch(E) {}
		}
		return yes;
	},

	getCommandImage: function(cmd) {
		if(cmd == "|") {
			return cmd;
		} else {
			return dojo.uri.dojoUri("src/widget/templates/buttons/" + cmd + ".gif");
		}
	},

	_action: function(e) {
		this._fire("onAction", e.getValue());
	},

	_setValue: function(a, b) {
		this._fire("onAction", a.getValue(), b);
	},

	_save: function(e){
		// FIXME: how should this behave when there's a larger form in play?
		if(!this._richText.isClosed){
			if(this.saveUrl.length){
				var content = {};
				content[this.saveArgName] = this.getHtml();
				dojo.io.bind({
					method: this.saveMethod,
					url: this.saveUrl,
					content: content
				});
			}else{
				dojo.debug("please set a saveUrl for the editor");
			}
			if(this.closeOnSave){
				this._richText.close(e.getName().toLowerCase() == "save");
			}
		}
	},

	_close: function(e) {
		if(!this._richText.isClosed) {
			this._richText.close(e.getName().toLowerCase() == "save");
		}
	},

	onAction: function(cmd, value) {
		switch(cmd) {
			case "createlink":
				if(!(value = prompt("Please enter the URL of the link:", "http://"))) {
					return;
				}
				break;
			case "insertimage":
				if(!(value = prompt("Please enter the URL of the image:", "http://"))) {
					return;
				}
				break;
		}
		this._richText.execCommand(cmd, value);
	},

	fillInTemplate: function(args, frag) {
		// dojo.event.connect(this, "onResized", this._richText, "onResized");
	},

	_fire: function(eventName) {
		if(dojo.lang.isFunction(this[eventName])) {
			var args = [];
			if(arguments.length == 1) {
				args.push(this);
			} else {
				for(var i = 1; i < arguments.length; i++) {
					args.push(arguments[i]);
				}
			}
			this[eventName].apply(this, args);
		}
	},

	getHtml: function(){
		this._richText.contentFilters = this._richText.contentFilters.concat(this.contentFilters);
		return this._richText.getEditorContent();
	},

	getEditorContent: function(){
		return this.getHtml();
	},

	onClose: function(save, hide){
		this.disableToolbar(hide);
		if(save) {
			this._fire("onSave");
		} else {
			this._fire("onCancel");
		}
	},

	// events baby!
	onLoad: function(){},
	onSave: function(){},
	onCancel: function(){}
});

