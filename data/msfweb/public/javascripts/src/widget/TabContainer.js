/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.TabContainer");
dojo.provide("dojo.widget.html.TabContainer");
dojo.provide("dojo.widget.Tab");

dojo.require("dojo.lang.func");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.event.*");
dojo.require("dojo.html");
dojo.require("dojo.style");
dojo.require("dojo.html.layout");

//////////////////////////////////////////
// TabContainer -- a set of Tabs
//////////////////////////////////////////
dojo.widget.html.TabContainer = function() {
	dojo.widget.HtmlWidget.call(this);
}

dojo.inherits(dojo.widget.html.TabContainer, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.html.TabContainer, {
	widgetType: "TabContainer",
    isContainer: true,

	// Constructor arguments
	labelPosition: "top",
	closeButton: "none",

	useVisibility: false,		// true-->use visibility:hidden instead of display:none
	
	// if false, TabContainers size changes according to size of currently selected tab
	doLayout: true,

	templatePath: dojo.uri.dojoUri("src/widget/templates/HtmlTabContainer.html"),
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlTabContainer.css"),

	selectedTab: "",		// initially selected tab (widgetId)

	fillInTemplate: function(args, frag) {
		// Copy style info from input node to output node
		var source = this.getFragNodeRef(frag);
		dojo.html.copyStyle(this.domNode, source);

		dojo.widget.html.TabContainer.superclass.fillInTemplate.call(this, args, frag);
	},

	postCreate: function(args, frag) {
		// Load all the tabs, creating a label for each one
		for(var i=0; i<this.children.length; i++){
			this._setupTab(this.children[i]);
		}

		if (this.closeButton=="pane") {
			var div = document.createElement("div");
			dojo.html.addClass(div, "dojoTabPanePaneClose");
			var self = this;
			dojo.event.connect(div, "onclick", function(){ self._runOnCloseTab(self.selectedTabWidget); });
			dojo.event.connect(div, "onmouseover", function(){ dojo.html.addClass(div, "dojoTabPanePaneCloseHover"); });
			dojo.event.connect(div, "onmouseout", function(){ dojo.html.removeClass(div, "dojoTabPanePaneCloseHover"); });
			this.dojoTabLabels.appendChild(div);
		}

		if(this.doLayout){
			dojo.html.addClass(this.dojoTabLabels, "dojoTabLabels-"+this.labelPosition);
		} else {
			dojo.html.addClass(this.dojoTabLabels, "dojoTabLabels-"+this.labelPosition+"-noLayout");
		}

        this._doSizing();

		// Display the selected tab
		if(this.selectedTabWidget){
			this.selectTab(this.selectedTabWidget, true);
		}
	},

	addChild: function(child, overrideContainerNode, pos, ref, insertIndex){
		this._setupTab(child);
		dojo.widget.html.TabContainer.superclass.addChild.call(this,child, overrideContainerNode, pos, ref, insertIndex);

		// in case the tab labels have overflowed from one line to two lines
		this._doSizing();
	},

	_setupTab: function(tab){
		tab.domNode.style.display="none";

		// Create label
		tab.div = document.createElement("div");
		dojo.widget.wai.setAttr(tab.div, "waiRole", "tab");
		dojo.html.addClass(tab.div, "dojoTabPaneTab");
		var span = document.createElement("span");
		span.innerHTML = tab.label;
		dojo.html.disableSelection(span);
		if (this.closeButton=="tab") {
			var img = document.createElement("div");
			dojo.html.addClass(img, "dojoTabPaneTabClose");
			var self = this;
			dojo.event.connect(img, "onclick", function(evt){ self._runOnCloseTab(tab); dojo.event.browser.stopEvent(evt); });
			dojo.event.connect(img, "onmouseover", function(){ dojo.html.addClass(img,"dojoTabPaneTabCloseHover"); });
			dojo.event.connect(img, "onmouseout", function(){ dojo.html.removeClass(img,"dojoTabPaneTabCloseHover"); });
			span.appendChild(img);
		}
		tab.div.appendChild(span);
		this.dojoTabLabels.appendChild(tab.div);
		
		var self = this;
		dojo.event.connect(tab.div, "onclick", function(){ self.selectTab(tab); });

		if(!this.selectedTabWidget || this.selectedTab==tab.widgetId || tab.selected){
    		this.selectedTabWidget = tab;
        } else {
            this._hideTab(tab);
        }

		dojo.html.addClass(tab.domNode, "dojoTabPane");
		with(tab.domNode.style){
			top = dojo.style.getPixelValue(this.containerNode, "padding-top", true);
			left = dojo.style.getPixelValue(this.containerNode, "padding-left", true);
		}
	},

	// Configure the content pane to take up all the space except for where the tab labels are
	_doSizing: function(){
		// position the labels and the container node
		var labelAlign=this.labelPosition.replace(/-h/,"");
		var children = [
			{domNode: this.dojoTabLabels, layoutAlign: labelAlign},
			{domNode: this.containerNode, layoutAlign: "client"}
		];


		if (this.doLayout) {
			dojo.html.layout(this.domNode, children);
		} 
			
		// size the current tab
		// TODO: should have ptr to current tab rather than searching
		var cw=dojo.style.getContentWidth(this.containerNode);
		var ch=dojo.style.getContentHeight(this.containerNode);
		dojo.lang.forEach(this.children, function(child){
			//if (this.doLayout) {
				if(child.selected){
					child.resizeTo(cw, ch);
				} 
			//} else {
			//	child.onResized();
			//}
		});
		
	},

    removeChild: function(tab) {

		// remove tab event handlers
		dojo.event.disconnect(tab.div, "onclick", function () { });
		if (this.closeButton=="tab") {
			var img = tab.div.lastChild.lastChild;
			if (img) {
				dojo.html.removeClass(img, "dojoTabPaneTabClose", function () { });
				dojo.event.disconnect(img, "onclick", function () { });
				dojo.event.disconnect(img, "onmouseover", function () { });
				dojo.event.disconnect(img, "onmouseout", function () { });
			}
		}

        dojo.widget.html.TabContainer.superclass.removeChild.call(this, tab);

        dojo.html.removeClass(tab.domNode, "dojoTabPane");
        this.dojoTabLabels.removeChild(tab.div);
        delete(tab.div);

        if (this.selectedTabWidget === tab) {
            this.selectedTabWidget = undefined;
            if (this.children.length > 0) {
                this.selectTab(this.children[0], true);
            }
        }

		// in case the tab labels have overflowed from one line to two lines
		this._doSizing();
    },

    selectTab: function(tab, _noRefresh) {
		// Deselect old tab and select new one
		if (this.selectedTabWidget) {
			this._hideTab(this.selectedTabWidget);
		}
		this.selectedTabWidget = tab;
		this._showTab(tab, _noRefresh);
	},

	_showTab: function(tab, _noRefresh) {
		dojo.html.addClass(tab.div, "current");
		tab.selected=true;
		if ( this.useVisibility && !dojo.render.html.ie ) {
			tab.domNode.style.visibility="visible";
		} else {
			// make sure we dont refresh onClose and on postCreate
			// speeds up things a bit when using refreshOnShow and fixes #646
			if(_noRefresh && tab.refreshOnShow){
				var tmp = tab.refreshOnShow;
				tab.refreshOnShow = false;
				tab.show();
				tab.refreshOnShow = tmp;
			}else{
				tab.show();
			}

			tab.resizeTo(
				dojo.style.getContentWidth(this.containerNode),
				dojo.style.getContentHeight(this.containerNode)
			);
		}
	},

	_hideTab: function(tab) {
		dojo.html.removeClass(tab.div, "current");
		tab.selected=false;
		if( this.useVisibility ){
			tab.domNode.style.visibility="hidden";
		}else{
			tab.hide();
		}
	},

	_runOnCloseTab: function(tab) {
		var onc = tab.extraArgs.onClose || tab.extraArgs.onclose;
		var fcn = dojo.lang.isFunction(onc) ? onc : window[onc];
		var remove = dojo.lang.isFunction(fcn) ? fcn(this,tab) : true;
		if(remove) {
			this.removeChild(tab);
			// makes sure we can clean up executeScripts in ContentPane onUnLoad
			tab.destroy();
		}
	},

	onResized: function() {
		this._doSizing();
	}
});
dojo.widget.tags.addParseTreeHandler("dojo:TabContainer");

// These arguments can be specified for the children of a TabContainer.
// Since any widget can be specified as a TabContainer child, mix them
// into the base widget class.  (This is a hack, but it's effective.)
dojo.lang.extend(dojo.widget.Widget, {
	label: "",
	selected: false	// is this tab currently selected?
});
