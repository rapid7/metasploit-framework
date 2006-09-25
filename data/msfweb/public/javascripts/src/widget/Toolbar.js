/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.ToolbarContainer");
dojo.provide("dojo.widget.html.ToolbarContainer");
dojo.provide("dojo.widget.Toolbar");
dojo.provide("dojo.widget.html.Toolbar");
dojo.provide("dojo.widget.ToolbarItem");
dojo.provide("dojo.widget.html.ToolbarButtonGroup");
dojo.provide("dojo.widget.html.ToolbarButton");
dojo.provide("dojo.widget.html.ToolbarDialog");
dojo.provide("dojo.widget.html.ToolbarMenu");
dojo.provide("dojo.widget.html.ToolbarSeparator");
dojo.provide("dojo.widget.html.ToolbarSpace");
dojo.provide("dojo.widget.Icon");

dojo.require("dojo.widget.*");
dojo.require("dojo.html");

/* ToolbarContainer
 *******************/
dojo.widget.tags.addParseTreeHandler("dojo:toolbarContainer");
dojo.widget.html.ToolbarContainer = function() {
	dojo.widget.HtmlWidget.call(this);
}
dojo.inherits(dojo.widget.html.ToolbarContainer, dojo.widget.HtmlWidget);
dojo.lang.extend(dojo.widget.html.ToolbarContainer, {
	widgetType: "ToolbarContainer",
	isContainer: true,

	templateString: '<div class="toolbarContainer" dojoAttachPoint="containerNode"></div>',
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlToolbar.css"),

	getItem: function(name) {
		if(name instanceof dojo.widget.ToolbarItem) { return name; }
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.html.Toolbar) {
				var item = child.getItem(name);
				if(item) { return item; }
			}
		}
		return null;
	},

	getItems: function() {
		var items = [];
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.html.Toolbar) {
				items = items.concat(child.getItems());
			}
		}
		return items;
	},

	enable: function() {
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.html.Toolbar) {
				child.enable.apply(child, arguments);
			}
		}
	},

	disable: function() {
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.html.Toolbar) {
				child.disable.apply(child, arguments);
			}
		}
	},

	select: function(name) {
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.html.Toolbar) {
				child.select(arguments);
			}
		}
	},

	deselect: function(name) {
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.html.Toolbar) {
				child.deselect(arguments);
			}
		}
	},

	getItemsState: function() {
		var values = {};
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.html.Toolbar) {
				dojo.lang.mixin(values, child.getItemsState());
			}
		}
		return values;
	},

	getItemsActiveState: function() {
		var values = {};
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.html.Toolbar) {
				dojo.lang.mixin(values, child.getItemsActiveState());
			}
		}
		return values;
	},

	getItemsSelectedState: function() {
		var values = {};
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.html.Toolbar) {
				dojo.lang.mixin(values, child.getItemsSelectedState());
			}
		}
		return values;
	}
});

/* Toolbar
 **********/
dojo.widget.tags.addParseTreeHandler("dojo:toolbar");
dojo.widget.html.Toolbar = function() {
	dojo.widget.HtmlWidget.call(this);
}
dojo.inherits(dojo.widget.html.Toolbar, dojo.widget.HtmlWidget);
dojo.lang.extend(dojo.widget.html.Toolbar, {
	widgetType: "Toolbar",
	isContainer: true,

	templateString: '<div class="toolbar" dojoAttachPoint="containerNode" unselectable="on" dojoOnMouseover="_onmouseover" dojoOnMouseout="_onmouseout" dojoOnClick="_onclick" dojoOnMousedown="_onmousedown" dojoOnMouseup="_onmouseup"></div>',
	//templateString: '<div class="toolbar" dojoAttachPoint="containerNode" unselectable="on"></div>',

	// given a node, tries to find it's toolbar item
	_getItem: function(node) {
		var start = new Date();
		var widget = null;
		while(node && node != this.domNode) {
			if(dojo.html.hasClass(node, "toolbarItem")) {
				var widgets = dojo.widget.manager.getWidgetsByFilter(function(w) { return w.domNode == node; });
				if(widgets.length == 1) {
					widget = widgets[0];
					break;
				} else if(widgets.length > 1) {
					dojo.raise("Toolbar._getItem: More than one widget matches the node");
				}
			}
			node = node.parentNode;
		}
		return widget;
	},

	_onmouseover: function(e) {
		var widget = this._getItem(e.target);
		if(widget && widget._onmouseover) { widget._onmouseover(e); }
	},

	_onmouseout: function(e) {
		var widget = this._getItem(e.target);
		if(widget && widget._onmouseout) { widget._onmouseout(e); }
	},

	_onclick: function(e) {
		var widget = this._getItem(e.target);
		if(widget && widget._onclick){ 
			widget._onclick(e);
		}
	},

	_onmousedown: function(e) {
		var widget = this._getItem(e.target);
		if(widget && widget._onmousedown) { widget._onmousedown(e); }
	},

	_onmouseup: function(e) {
		var widget = this._getItem(e.target);
		if(widget && widget._onmouseup) { widget._onmouseup(e); }
	},

	addChild: function(item, pos, props) {
		var widget = dojo.widget.ToolbarItem.make(item, null, props);
		var ret = dojo.widget.html.Toolbar.superclass.addChild.call(this, widget, null, pos, null);
		return ret;
	},

	push: function() {
		for(var i = 0; i < arguments.length; i++) {
			this.addChild(arguments[i]);
		}
	},

	getItem: function(name) {
		if(name instanceof dojo.widget.ToolbarItem) { return name; }
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.ToolbarItem
				&& child._name == name) { return child; }
		}
		return null;
	},

	getItems: function() {
		var items = [];
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.ToolbarItem) {
				items.push(child);
			}
		}
		return items;
	},

	getItemsState: function() {
		var values = {};
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.ToolbarItem) {
				values[child._name] = {
					selected: child._selected,
					enabled: child._enabled
				};
			}
		}
		return values;
	},

	getItemsActiveState: function() {
		var values = this.getItemsState();
		for(var item in values) {
			values[item] = values[item].enabled;
		}
		return values;
	},

	getItemsSelectedState: function() {
		var values = this.getItemsState();
		for(var item in values) {
			values[item] = values[item].selected;
		}
		return values;
	},

	enable: function() {
		var items = arguments.length ? arguments : this.children;
		for(var i = 0; i < items.length; i++) {
			var child = this.getItem(items[i]);
			if(child instanceof dojo.widget.ToolbarItem) {
				child.enable(false, true);
			}
		}
	},

	disable: function() {
		var items = arguments.length ? arguments : this.children;
		for(var i = 0; i < items.length; i++) {
			var child = this.getItem(items[i]);
			if(child instanceof dojo.widget.ToolbarItem) {
				child.disable();
			}
		}
	},

	select: function() {
		for(var i = 0; i < arguments.length; i++) {
			var name = arguments[i];
			var item = this.getItem(name);
			if(item) { item.select(); }
		}
	},

	deselect: function() {
		for(var i = 0; i < arguments.length; i++) {
			var name = arguments[i];
			var item = this.getItem(name);
			if(item) { item.disable(); }
		}
	},

	setValue: function() {
		for(var i = 0; i < arguments.length; i += 2) {
			var name = arguments[i], value = arguments[i+1];
			var item = this.getItem(name);
			if(item) {
				if(item instanceof dojo.widget.ToolbarItem) {
					item.setValue(value);
				}
			}
		}
	}
});

/* ToolbarItem hierarchy:
	- ToolbarItem
		- ToolbarButton
		- ToolbarDialog
			- ToolbarMenu
		- ToolbarSeparator
			- ToolbarSpace
				- ToolbarFlexibleSpace
*/


/* ToolbarItem
 **************/
dojo.widget.ToolbarItem = function() {
	dojo.widget.HtmlWidget.call(this);
}
dojo.inherits(dojo.widget.ToolbarItem, dojo.widget.HtmlWidget);
dojo.lang.extend(dojo.widget.ToolbarItem, {
	templateString: '<span unselectable="on" class="toolbarItem"></span>',

	_name: null,
	getName: function() { return this._name; },
	setName: function(value) { return this._name = value; },
	getValue: function() { return this.getName(); },
	setValue: function(value) { return this.setName(value); },

	_selected: false,
	isSelected: function() { return this._selected; },
	setSelected: function(is, force, preventEvent) {
		if(!this._toggleItem && !force) { return; }
		is = Boolean(is);
		if(force || this._enabled && this._selected != is) {
			this._selected = is;
			this.update();
			if(!preventEvent) {
				this._fireEvent(is ? "onSelect" : "onDeselect");
				this._fireEvent("onChangeSelect");
			}
		}
	},
	select: function(force, preventEvent) {
		return this.setSelected(true, force, preventEvent);
	},
	deselect: function(force, preventEvent) {
		return this.setSelected(false, force, preventEvent);
	},

	_toggleItem: false,
	isToggleItem: function() { return this._toggleItem; },
	setToggleItem: function(value) { this._toggleItem = Boolean(value); },

	toggleSelected: function(force) {
		return this.setSelected(!this._selected, force);
	},

	_enabled: true,
	isEnabled: function() { return this._enabled; },
	setEnabled: function(is, force, preventEvent) {
		is = Boolean(is);
		if(force || this._enabled != is) {
			this._enabled = is;
			this.update();
			if(!preventEvent) {
				this._fireEvent(this._enabled ? "onEnable" : "onDisable");
				this._fireEvent("onChangeEnabled");
			}
		}
		return this._enabled;
	},
	enable: function(force, preventEvent) {
		return this.setEnabled(true, force, preventEvent);
	},
	disable: function(force, preventEvent) {
		return this.setEnabled(false, force, preventEvent);
	},
	toggleEnabled: function(force, preventEvent) {
		return this.setEnabled(!this._enabled, force, preventEvent);
	},

	_icon: null,
	getIcon: function() { return this._icon; },
	setIcon: function(value) {
		var icon = dojo.widget.Icon.make(value);
		if(this._icon) {
			this._icon.setIcon(icon);
		} else {
			this._icon = icon;
		}
		var iconNode = this._icon.getNode();
		if(iconNode.parentNode != this.domNode) {
			if(this.domNode.hasChildNodes()) {
				this.domNode.insertBefore(iconNode, this.domNode.firstChild);
			} else {
				this.domNode.appendChild(iconNode);
			}
		}
		return this._icon;
	},

	// TODO: update the label node (this.labelNode?)
	_label: "",
	getLabel: function() { return this._label; },
	setLabel: function(value) {
		var ret = this._label = value;
		if(!this.labelNode) {
			this.labelNode = document.createElement("span");
			this.domNode.appendChild(this.labelNode);
		}
		this.labelNode.innerHTML = "";
		this.labelNode.appendChild(document.createTextNode(this._label));
		this.update();
		return ret;
	},

	// fired from: setSelected, setEnabled, setLabel
	update: function() {
		if(this._enabled) {
			dojo.html.removeClass(this.domNode, "disabled");
			if(this._selected) {
				dojo.html.addClass(this.domNode, "selected");
			} else {
				dojo.html.removeClass(this.domNode, "selected");
			}
		} else {
			this._selected = false;
			dojo.html.addClass(this.domNode, "disabled");
			dojo.html.removeClass(this.domNode, "down");
			dojo.html.removeClass(this.domNode, "hover");
		}
		this._updateIcon();
	},

	_updateIcon: function() {
		if(this._icon) {
			if(this._enabled) {
				if(this._cssHover) {
					this._icon.hover();
				} else if(this._selected) {
					this._icon.select();
				} else {
					this._icon.enable();
				}
			} else {
				this._icon.disable();
			}
		}
	},

	_fireEvent: function(evt) {
		if(typeof this[evt] == "function") {
			var args = [this];
			for(var i = 1; i < arguments.length; i++) {
				args.push(arguments[i]);
			}
			this[evt].apply(this, args);
		}
	},

	_onmouseover: function(e) {
		if(!this._enabled) { return };
		dojo.html.addClass(this.domNode, "hover");
	},

	_onmouseout: function(e) {
		dojo.html.removeClass(this.domNode, "hover");
		dojo.html.removeClass(this.domNode, "down");
		if(!this._selected) {
			dojo.html.removeClass(this.domNode, "selected");
		}
	},

	_onclick: function(e) {
		// FIXME: buttons never seem to have this._enabled set to true on Opera 9
		// dojo.debug("widget:", this.widgetType, ":", this.getName(), ", enabled:", this._enabled);
		if(this._enabled && !this._toggleItem) {
			this._fireEvent("onClick");
		}
	},

	_onmousedown: function(e) {
		if(e.preventDefault) { e.preventDefault(); }
		if(!this._enabled) { return };
		dojo.html.addClass(this.domNode, "down");
		if(this._toggleItem) {
			if(this.parent.preventDeselect && this._selected) {
				return;
			}
			this.toggleSelected();
		}
	},

	_onmouseup: function(e) {
		dojo.html.removeClass(this.domNode, "down");
	},

	fillInTemplate: function(args, frag) {
		if(args.name) { this._name = args.name; }
		if(args.selected) { this.select(); }
		if(args.disabled) { this.disable(); }
		if(args.label) { this.setLabel(args.label); }
		if(args.icon) { this.setIcon(args.icon); }
		if(args.toggleitem||args.toggleItem) { this.setToggleItem(true); }
	}
});

dojo.widget.ToolbarItem.make = function(wh, whIsType, props) {
	var item = null;

	if(wh instanceof Array) {
		item = dojo.widget.createWidget("ToolbarButtonGroup", props);
		item.setName(wh[0]);
		for(var i = 1; i < wh.length; i++) {
			item.addChild(wh[i]);
		}
	} else if(wh instanceof dojo.widget.ToolbarItem) {
		item = wh;
	} else if(wh instanceof dojo.uri.Uri) {
		item = dojo.widget.createWidget("ToolbarButton",
			dojo.lang.mixin(props||{}, {icon: new dojo.widget.Icon(wh.toString())}));
	} else if(whIsType) {
		item = dojo.widget.createWidget(wh, props)
	} else if(typeof wh == "string" || wh instanceof String) {
		switch(wh.charAt(0)) {
			case "|":
			case "-":
			case "/":
				item = dojo.widget.createWidget("ToolbarSeparator", props);
				break;
			case " ":
				if(wh.length == 1) {
					item = dojo.widget.createWidget("ToolbarSpace", props);
				} else {
					item = dojo.widget.createWidget("ToolbarFlexibleSpace", props);
				}
				break;
			default:
				if(/\.(gif|jpg|jpeg|png)$/i.test(wh)) {
					item = dojo.widget.createWidget("ToolbarButton",
						dojo.lang.mixin(props||{}, {icon: new dojo.widget.Icon(wh.toString())}));
				} else {
					item = dojo.widget.createWidget("ToolbarButton",
						dojo.lang.mixin(props||{}, {label: wh.toString()}));
				}
		}
	} else if(wh && wh.tagName && /^img$/i.test(wh.tagName)) {
		item = dojo.widget.createWidget("ToolbarButton",
			dojo.lang.mixin(props||{}, {icon: wh}));
	} else {
		item = dojo.widget.createWidget("ToolbarButton",
			dojo.lang.mixin(props||{}, {label: wh.toString()}));
	}
	return item;
}

/* ToolbarButtonGroup
 *********************/
dojo.widget.tags.addParseTreeHandler("dojo:toolbarButtonGroup");
dojo.widget.html.ToolbarButtonGroup = function() {
	dojo.widget.ToolbarItem.call(this);
}
dojo.inherits(dojo.widget.html.ToolbarButtonGroup, dojo.widget.ToolbarItem);
dojo.lang.extend(dojo.widget.html.ToolbarButtonGroup, {
	widgetType: "ToolbarButtonGroup",
	isContainer: true,

	templateString: '<span unselectable="on" class="toolbarButtonGroup" dojoAttachPoint="containerNode"></span>',

	// if a button has the same name, it will be selected
	// if this is set to a number, the button at that index will be selected
	defaultButton: "",

    postCreate: function() {
        for (var i = 0; i < this.children.length; i++) {
            this._injectChild(this.children[i]);
        }
    },

	addChild: function(item, pos, props) {
		var widget = dojo.widget.ToolbarItem.make(item, null, dojo.lang.mixin(props||{}, {toggleItem:true}));
		var ret = dojo.widget.html.ToolbarButtonGroup.superclass.addChild.call(this, widget, null, pos, null);
        this._injectChild(widget);
        return ret;
    },

    _injectChild: function(widget) {
        dojo.event.connect(widget, "onSelect", this, "onChildSelected");
        dojo.event.connect(widget, "onDeselect", this, "onChildDeSelected");
        if(widget._name == this.defaultButton
			|| (typeof this.defaultButton == "number"
			&& this.children.length-1 == this.defaultButton)) {
			widget.select(false, true);
		}
	},

	getItem: function(name) {
		if(name instanceof dojo.widget.ToolbarItem) { return name; }
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.ToolbarItem
				&& child._name == name) { return child; }
		}
		return null;
	},

	getItems: function() {
		var items = [];
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.ToolbarItem) {
				items.push(child);
			}
		}
		return items;
	},

	onChildSelected: function(e) {
		this.select(e._name);
	},

	onChildDeSelected: function(e) {
		this._fireEvent("onChangeSelect", this._value);
	},

	enable: function(force, preventEvent) {
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.ToolbarItem) {
				child.enable(force, preventEvent);
				if(child._name == this._value) {
					child.select(force, preventEvent);
				}
			}
		}
	},

	disable: function(force, preventEvent) {
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.ToolbarItem) {
				child.disable(force, preventEvent);
			}
		}
	},

	_value: "",
	getValue: function() { return this._value; },

	select: function(name, force, preventEvent) {
		for(var i = 0; i < this.children.length; i++) {
			var child = this.children[i];
			if(child instanceof dojo.widget.ToolbarItem) {
				if(child._name == name) {
					child.select(force, preventEvent);
					this._value = name;
				} else {
					child.deselect(true, true);
				}
			}
		}
		if(!preventEvent) {
			this._fireEvent("onSelect", this._value);
			this._fireEvent("onChangeSelect", this._value);
		}
	},
	setValue: this.select,

	preventDeselect: false // if true, once you select one, you can't have none selected
});

/* ToolbarButton
 ***********************/
dojo.widget.tags.addParseTreeHandler("dojo:toolbarButton");
dojo.widget.html.ToolbarButton = function() {
	dojo.widget.ToolbarItem.call(this);
}
dojo.inherits(dojo.widget.html.ToolbarButton, dojo.widget.ToolbarItem);
dojo.lang.extend(dojo.widget.html.ToolbarButton, {
	widgetType: "ToolbarButton",

	fillInTemplate: function(args, frag) {
		dojo.widget.html.ToolbarButton.superclass.fillInTemplate.call(this, args, frag);
		dojo.html.addClass(this.domNode, "toolbarButton");
		if(this._icon) {
			this.setIcon(this._icon);
		}
		if(this._label) {
			this.setLabel(this._label);
		}

		if(!this._name) {
			if(this._label) {
				this.setName(this._label);
			} else if(this._icon) {
				var src = this._icon.getSrc("enabled").match(/[\/^]([^\.\/]+)\.(gif|jpg|jpeg|png)$/i);
				if(src) { this.setName(src[1]); }
			} else {
				this._name = this._widgetId;
			}
		}
	}
});

/* ToolbarDialog
 **********************/
dojo.widget.tags.addParseTreeHandler("dojo:toolbarDialog");
dojo.widget.html.ToolbarDialog = function() {
	dojo.widget.html.ToolbarButton.call(this);
}
dojo.inherits(dojo.widget.html.ToolbarDialog, dojo.widget.html.ToolbarButton);
dojo.lang.extend(dojo.widget.html.ToolbarDialog, {
	widgetType: "ToolbarDialog",
	
	fillInTemplate: function (args, frag) {
		dojo.widget.html.ToolbarDialog.superclass.fillInTemplate.call(this, args, frag);
		dojo.event.connect(this, "onSelect", this, "showDialog");
		dojo.event.connect(this, "onDeselect", this, "hideDialog");
	},
	
	showDialog: function (e) {
		dojo.lang.setTimeout(dojo.event.connect, 1, document, "onmousedown", this, "deselect");
	},
	
	hideDialog: function (e) {
		dojo.event.disconnect(document, "onmousedown", this, "deselect");
	}

});

/* ToolbarMenu
 **********************/
dojo.widget.tags.addParseTreeHandler("dojo:toolbarMenu");
dojo.widget.html.ToolbarMenu = function() {
	dojo.widget.html.ToolbarDialog.call(this);

	this.widgetType = "ToolbarMenu";
}
dojo.inherits(dojo.widget.html.ToolbarMenu, dojo.widget.html.ToolbarDialog);

/* ToolbarMenuItem
 ******************/
dojo.widget.ToolbarMenuItem = function() {
}

/* ToolbarSeparator
 **********************/
dojo.widget.tags.addParseTreeHandler("dojo:toolbarSeparator");
dojo.widget.html.ToolbarSeparator = function() {
    dojo.widget.ToolbarItem.call(this);
}
dojo.inherits(dojo.widget.html.ToolbarSeparator, dojo.widget.ToolbarItem);
dojo.lang.extend(dojo.widget.html.ToolbarSeparator, {
	widgetType: "ToolbarSeparator",
	templateString: '<span unselectable="on" class="toolbarItem toolbarSeparator"></span>',

	defaultIconPath: new dojo.uri.dojoUri("src/widget/templates/buttons/-.gif"),

	fillInTemplate: function(args, frag, skip) {
		dojo.widget.html.ToolbarSeparator.superclass.fillInTemplate.call(this, args, frag);
		this._name = this.widgetId;
		if(!skip) {
			if(!this._icon) {
				this.setIcon(this.defaultIconPath);
			}
			this.domNode.appendChild(this._icon.getNode());
		}
	},

	// don't want events!
	_onmouseover: null, 
    _onmouseout: null, 
    _onclick: null, 
    _onmousedown: null, 
    _onmouseup: null 
});

/* ToolbarSpace
 **********************/
dojo.widget.tags.addParseTreeHandler("dojo:toolbarSpace");
dojo.widget.html.ToolbarSpace = function() {
	dojo.widget.html.ToolbarSeparator.call(this);
}
dojo.inherits(dojo.widget.html.ToolbarSpace, dojo.widget.html.ToolbarSeparator);
dojo.lang.extend(dojo.widget.html.ToolbarSpace, {
    widgetType: "ToolbarSpace",

	fillInTemplate: function(args, frag, skip) {
		dojo.widget.html.ToolbarSpace.superclass.fillInTemplate.call(this, args, frag, true);
		if(!skip) {
			dojo.html.addClass(this.domNode, "toolbarSpace");
		}
	}
});

/* ToolbarSelect
 ******************/ 

dojo.widget.tags.addParseTreeHandler("dojo:toolbarSelect");
dojo.widget.html.ToolbarSelect = function() {
	dojo.widget.ToolbarItem.call(this);
}
dojo.inherits(dojo.widget.html.ToolbarSelect, dojo.widget.ToolbarItem);
dojo.lang.extend(dojo.widget.html.ToolbarSelect, {
    widgetType: "ToolbarSelect",
	templateString: '<span class="toolbarItem toolbarSelect" unselectable="on"><select dojoAttachPoint="selectBox" dojoOnChange="changed"></select></span>',

	fillInTemplate: function(args, frag) {
		dojo.widget.html.ToolbarSelect.superclass.fillInTemplate.call(this, args, frag, true);
		var keys = args.values;
		var i = 0;
		for(var val in keys) {
			var opt = document.createElement("option");
			opt.setAttribute("value", keys[val]);
			opt.innerHTML = val;
			this.selectBox.appendChild(opt);
		}
	},

	changed: function(e) {
		this._fireEvent("onSetValue", this.selectBox.value);
	},

	setEnabled: function(is, force, preventEvent) {
		var ret = dojo.widget.html.ToolbarSelect.superclass.setEnabled.call(this, is, force, preventEvent);
		this.selectBox.disabled = !this._enabled;
		return ret;
	},

	// don't want events!
	_onmouseover: null,
    _onmouseout: null,
    _onclick: null,
    _onmousedown: null,
    _onmouseup: null
});

/* Icon
 *********/
// arguments can be IMG nodes, Image() instances or URLs -- enabled is the only one required
dojo.widget.Icon = function(enabled, disabled, hover, selected){
	if(!arguments.length){
		// FIXME: should this be dojo.raise?
		throw new Error("Icon must have at least an enabled state");
	}
	var states = ["enabled", "disabled", "hover", "selected"];
	var currentState = "enabled";
	var domNode = document.createElement("img");

	this.getState = function(){ return currentState; }
	this.setState = function(value){
		if(dojo.lang.inArray(value, states)){
			if(this[value]){
				currentState = value;
				domNode.setAttribute("src", this[currentState].src);
			}
		}else{
			throw new Error("Invalid state set on Icon (state: " + value + ")");
		}
	}

	this.setSrc = function(state, value){
		if(/^img$/i.test(value.tagName)){
			this[state] = value;
		}else if(typeof value == "string" || value instanceof String
			|| value instanceof dojo.uri.Uri){
			this[state] = new Image();
			this[state].src = value.toString();
		}
		return this[state];
	}

	this.setIcon = function(icon){
		for(var i = 0; i < states.length; i++){
			if(icon[states[i]]){
				this.setSrc(states[i], icon[states[i]]);
			}
		}
		this.update();
	}

	this.enable = function(){ this.setState("enabled"); }
	this.disable = function(){ this.setState("disabled"); }
	this.hover = function(){ this.setState("hover"); }
	this.select = function(){ this.setState("selected"); }

	this.getSize = function(){
		return {
			width: domNode.width||domNode.offsetWidth,
			height: domNode.height||domNode.offsetHeight
		};
	}

	this.setSize = function(w, h){
		domNode.width = w;
		domNode.height = h;
		return { width: w, height: h };
	}

	this.getNode = function(){
		return domNode;
	}

	this.getSrc = function(state){
		if(state){ return this[state].src; }
		return domNode.src||"";
	}

	this.update = function(){
		this.setState(currentState);
	}

	for(var i = 0; i < states.length; i++){
		var arg = arguments[i];
		var state = states[i];
		this[state] = null;
		if(!arg){ continue; }
		this.setSrc(state, arg);
	}

	this.enable();
}

dojo.widget.Icon.make = function(a,b,c,d){
	for(var i = 0; i < arguments.length; i++){
		if(arguments[i] instanceof dojo.widget.Icon){
			return arguments[i];
		}
	}

	return new dojo.widget.Icon(a,b,c,d);
}
