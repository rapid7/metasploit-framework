/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.Menu2");
dojo.provide("dojo.widget.html.Menu2");
dojo.provide("dojo.widget.PopupMenu2");
dojo.provide("dojo.widget.MenuItem2");
dojo.provide("dojo.widget.MenuBar2");

dojo.require("dojo.html");
dojo.require("dojo.style");
dojo.require("dojo.event.*");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.HtmlWidget");


dojo.widget.PopupMenu2 = function(){
	dojo.widget.HtmlWidget.call(this);
	this.items = [];	// unused???
	this.targetNodeIds = []; // fill this with nodeIds upon widget creation and it becomes context menu for those nodes
	this.queueOnAnimationFinish = [];

	this.eventNames =  {
		open: ""
	};

}

dojo.inherits(dojo.widget.PopupMenu2, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.PopupMenu2, {
	widgetType: "PopupMenu2",
	isContainer: true,

	snarfChildDomOutput: true,

	currentSubmenu: null,
	currentSubmenuTrigger: null,
	parentMenu: null,
	parentMenuBar: null,
	isShowingNow: false,
	menuX: 0,
	menuY: 0,
	menuWidth: 0,
	menuHeight: 0,
	menuIndex: 0,

	domNode: null,
	containerNode: null,

	eventNaming: "default",


	templateString: '<div class="dojoPopupMenu2" style="left:-9999px; top:-9999px; display: none;"><div dojoAttachPoint="containerNode" class="dojoPopupMenu2Client"></div></div>',
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlMenu2.css"),

	itemHeight: 18,
	iconGap: 1,
	accelGap: 10,
	submenuGap: 2,
	finalGap: 5,
	submenuIconSize: 4,
	separatorHeight: 9,
	submenuDelay: 500,
	submenuOverlap: 5,
	contextMenuForWindow: false,
	openEvent: null,

	submenuIconSrc: dojo.uri.dojoUri("src/widget/templates/images/submenu_off.gif").toString(),
	submenuIconOnSrc: dojo.uri.dojoUri("src/widget/templates/images/submenu_on.gif").toString(),

	initialize: function(args, frag) {

		if (this.eventNaming == "default") {
			for (var eventName in this.eventNames) {
				this.eventNames[eventName] = this.widgetId+"/"+eventName;
			}
		}

	},

	postCreate: function(){
		if (this.domNode.style.display=="none"){
			this.domNode.style.display = "";
		}
		this.domNode.style.left = '-9999px'
		this.domNode.style.top = '-9999px'

		// attach menu to document body if it's not already there
		if (this.domNode.parentNode != document.body){
			document.body.appendChild(this.domNode);
		}


		if (this.contextMenuForWindow){
			var doc = document.documentElement  || document.body;
			dojo.widget.Menu2.OperaAndKonqFixer.fixNode(doc);
			dojo.event.connect(doc, "oncontextmenu", this, "onOpen");
		} else if ( this.targetNodeIds.length > 0 ){
			for(var i=0; i<this.targetNodeIds.length; i++){
				this.bindDomNode(this.targetNodeIds[i]);
			}
		}

		this.subscribeSubitemsOnOpen();

		this.layoutMenuSoon();
	},

	subscribeSubitemsOnOpen: function() {
		var subItems = this.getChildrenOfType(dojo.widget.MenuItem2);

		//dojo.debug(subItems)

		for(var i=0; i<subItems.length; i++) {
			//dojo.debug(subItems[i]);
			dojo.event.topic.subscribe(this.eventNames.open, subItems[i], "menuOpen")
		}
	},

	// get open event for current menu
	getTopOpenEvent: function() {
		var menu = this;
		while (menu.parent){ menu = menu.parent; }
		return menu.openEvent;
	},

	// attach menu to given node
	bindDomNode: function(nodeName){
		var node = dojo.byId(nodeName);

		// fixes node so that it supports oncontextmenu if not natively supported, Konqueror, Opera more?
		dojo.widget.Menu2.OperaAndKonqFixer.fixNode(node);

		dojo.event.kwConnect({
			srcObj:     node,
			srcFunc:    "oncontextmenu",
			targetObj:  this,
			targetFunc: "onOpen",
			once:       true
		});
	},

	// detach menu from given node
	unBindDomNode: function(nodeName){
		var node = dojo.byId(nodeName);
		dojo.event.kwDisconnect({
			srcObj:     node,
			srcFunc:    "oncontextmenu",
			targetObj:  this,
			targetFunc: "onOpen",
			once:       true
		});

		// cleans a fixed node, konqueror and opera
		dojo.widget.Menu2.OperaAndKonqFixer.cleanNode(node);
	},

	layoutMenuSoon: function(){
		dojo.lang.setTimeout(this, "layoutMenu", 0);
	},

	layoutMenu: function(){

        // menu must be attached to DOM for size calculations to work
		// even though we attached to document.body in postCreate(), here
		// we seem to be attached to a #document-fragment.  Don't understand why.
        document.body.appendChild(this.domNode);

        // determine menu width
		var max_label_w = 0;
		var max_accel_w = 0;

		for(var i=0; i<this.children.length; i++){
			if (this.children[i].getLabelWidth){
				max_label_w = Math.max(max_label_w, this.children[i].getLabelWidth());
			}

			if (dojo.lang.isFunction(this.children[i].getAccelWidth)){
				max_accel_w = Math.max(max_accel_w, this.children[i].getAccelWidth());
			}
		}

		if( isNaN(max_label_w) || isNaN(max_accel_w) ){
			// Browser needs some more time to calculate sizes
			this.layoutMenuSoon();
			return;
		}

		var clientLeft = dojo.style.getPixelValue(this.domNode, "padding-left", true) + dojo.style.getPixelValue(this.containerNode, "padding-left", true);
		var clientTop  = dojo.style.getPixelValue(this.domNode, "padding-top", true)  + dojo.style.getPixelValue(this.containerNode, "padding-top", true);

		if( isNaN(clientLeft) || isNaN(clientTop) ){
			// Browser needs some more time to calculate sizes
			this.layoutMenuSoon();
			return;
		}

		var y = clientTop;
		var max_item_width = 0;

		for(var i=0; i<this.children.length; i++){

			var ch = this.children[i];

			ch.layoutItem(max_label_w, max_accel_w);

			ch.topPosition = y;

			y += dojo.style.getOuterHeight(ch.domNode);
			max_item_width = Math.max(max_item_width, dojo.style.getOuterWidth(ch.domNode));
		}

		dojo.style.setContentWidth(this.containerNode, max_item_width);
		dojo.style.setContentHeight(this.containerNode, y-clientTop);

		dojo.style.setContentWidth(this.domNode, dojo.style.getOuterWidth(this.containerNode));
		dojo.style.setContentHeight(this.domNode, dojo.style.getOuterHeight(this.containerNode));

		this.menuWidth = dojo.style.getOuterWidth(this.domNode);
		this.menuHeight = dojo.style.getOuterHeight(this.domNode);
	},

	/**
	 * Open the menu at position (x,y), relative to the viewport
	 * (usually positions are relative to the document; why is this different??)
	 */
	open: function(x, y, parent, explodeSrc){

		// if explodeSrc isn't specified then explode from my parent widget
		explodeSrc = explodeSrc || parent["domNode"] || [];

		if (this.isShowingNow){ return; }

		var parentMenu = (parent && parent.widgetType=="PopupMenu2") ? parent : null;

		if ( !parentMenu ) {
			// record whenever a top level menu is opened
			// explodeSrc may or may not be a node - it may also be an [x,y] position array
			var button = explodeSrc instanceof Array ? null : explodeSrc;
			dojo.widget.html.Menu2Manager.opened(this, button);
		}

		//dojo.debug("open called for animation "+this.animationInProgress)

		// if I click  right button and menu is opened, then it gets 2 commands: close -> open
		// so close enables animation and next "open" is put to queue to occur at new location
		if(this.animationInProgress){
			this.queueOnAnimationFinish.push(this.open, arguments);
			return;
		}

		var viewport = dojo.html.getViewportSize();
		var scrolloffset = dojo.html.getScrollOffset();

		var clientRect = {
			'left'  : scrolloffset[0],
			'right' : scrolloffset[0] + viewport[0],
			'top'   : scrolloffset[1],
			'bottom': scrolloffset[1] + viewport[1]
		};

		if (parentMenu){
			// submenu is opening

			if (x + this.menuWidth > clientRect.right){ x = x - (this.menuWidth + parentMenu.menuWidth - (2 * this.submenuOverlap)); }

			if (y + this.menuHeight > clientRect.bottom){ y = y -
			(this.menuHeight - (this.itemHeight + 5)); } // TODO: why 5?

		}else{
			// top level menu is opening
			x+=scrolloffset[0];
			y+=scrolloffset[1];
			explodeSrc[0] += scrolloffset[0];
			explodeSrc[1] += scrolloffset[1];

			if (x < clientRect.left){ x = clientRect.left; }
			if (x + this.menuWidth > clientRect.right){ x = x - this.menuWidth; }

			if (y < clientRect.top){ y = clientRect.top; }
			if (y + this.menuHeight > clientRect.bottom){ y = y - this.menuHeight; }
		}

		this.parentMenu = parentMenu;
		this.explodeSrc = explodeSrc;
		this.menuIndex = parentMenu ? parentMenu.menuIndex + 1 : 1;

		this.menuX = x;
		this.menuY = y;

		// move the menu into position but make it invisible
		// (because when menus are initially constructed they are visible but off-screen)
		this.domNode.style.zIndex = 200 + this.menuIndex;
		this.domNode.style.left = x + 'px';
		this.domNode.style.top = y + 'px';
		this.domNode.style.display='none';
		this.domNode.style.position='absolute';

		// then use the user defined method to display it
		this.show();

		this.isShowingNow = true;
	},

	close: function(){
		// If we are in the process of opening the menu and we are asked to close it,
		// we should really cancel the current animation, but for simplicity we will
		// just ignore the request
		if(this.animationInProgress){
			this.queueOnAnimationFinish.push(this.close, []);
			return;
		}

		this.closeSubmenu();
		this.hide();
		this.isShowingNow = false;
		dojo.widget.html.Menu2Manager.closed(this);

		if (this.parentMenuBar){
			this.parentMenuBar.closedMenu(this);
		}
	},

	onShow: function() {
		dojo.widget.HtmlWidget.prototype.onShow.call(this);
		this.processQueue();
	},

	// do events from queue
	processQueue: function() {
		if (!this.queueOnAnimationFinish.length) return;

		var func = this.queueOnAnimationFinish.shift();
		var args = this.queueOnAnimationFinish.shift();

		func.apply(this, args);
	},

	onHide: function() {
		dojo.widget.HtmlWidget.prototype.onHide.call(this);

		this.processQueue();
	},


	closeAll: function(){
		if (this.parentMenu){
			this.parentMenu.closeAll();
		}else{
			this.close();
		}
	},

	closeSubmenu: function(){
		if (this.currentSubmenu == null){ return; }

		this.currentSubmenu.close();
		this.currentSubmenu = null;

		this.currentSubmenuTrigger.is_open = false;
		this.currentSubmenuTrigger.closedSubmenu();
		this.currentSubmenuTrigger = null;
	},

	openSubmenu: function(submenu, from_item){

		var our_x = dojo.style.getPixelValue(this.domNode, 'left');
		var our_y = dojo.style.getPixelValue(this.domNode, 'top');
		var our_w = dojo.style.getOuterWidth(this.domNode);
		var item_y = from_item.topPosition;

		var x = our_x + our_w - this.submenuOverlap;
		var y = our_y + item_y;

		this.currentSubmenu = submenu;
		this.currentSubmenu.open(x, y, this, from_item.domNode);

		this.currentSubmenuTrigger = from_item;
		this.currentSubmenuTrigger.is_open = true;
	},

	onOpen: function(e){
		this.openEvent = e;

		//dojo.debugShallow(e);
		this.open(e.clientX, e.clientY, null, [e.clientX, e.clientY]);

		if(e["preventDefault"]){
			e.preventDefault();
		}
	},

	isPointInMenu: function(x, y){

		if (x < this.menuX){ return false; }
		if (x > this.menuX + this.menuWidth){ return false; }

		if (y < this.menuY){ return false; }
		if (y > this.menuY + this.menuHeight){ return false; }

		return true;
	}
});


dojo.widget.MenuItem2 = function(){
	dojo.widget.HtmlWidget.call(this);

	this.eventNames = {
		engage: ""
	};
}

dojo.inherits(dojo.widget.MenuItem2, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.MenuItem2, {
	widgetType: "MenuItem2",
	templateString:
			 '<div class="dojoMenuItem2">'
			+'<div dojoAttachPoint="iconNode" class="dojoMenuItem2Icon"></div>'
			+'<span dojoAttachPoint="labelNode" class="dojoMenuItem2Label"><span><span></span></span></span>'
			+'<span dojoAttachPoint="accelNode" class="dojoMenuItem2Accel"><span><span></span></span></span>'
			+'<div dojoAttachPoint="submenuNode" class="dojoMenuItem2Submenu"></div>'
			+'<div dojoAttachPoint="targetNode" class="dojoMenuItem2Target" dojoAttachEvent="onMouseOver: onHover; onMouseOut: onUnhover; onClick: _onClick;">&nbsp;</div>'
			+'</div>',

	//
	// nodes
	//

	domNode: null,
	iconNode: null,
	labelNode: null,
	accelNode: null,
	submenuNode: null,
	targetNode: null,

	//
	// internal settings
	//

	is_hovering: false,
	hover_timer: null,
	is_open: false,
	topPosition: 0,

	//
	// options
	//

	caption: 'Untitled',
	accelKey: '',
	iconSrc: '',
	submenuId: '',
	disabled: false,
	eventNaming: "default",


	postCreate: function(){

		dojo.html.disableSelection(this.domNode);

		if (this.disabled){
			this.setDisabled(true);
		}

		this.labelNode.childNodes[0].appendChild(document.createTextNode(this.caption));
		this.accelNode.childNodes[0].appendChild(document.createTextNode(this.accelKey));

		this.labelShadowNode = this.labelNode.childNodes[0].childNodes[0];
		this.accelShadowNode = this.accelNode.childNodes[0].childNodes[0];

		this.labelShadowNode.appendChild(document.createTextNode(this.caption));
		this.accelShadowNode.appendChild(document.createTextNode(this.accelKey));

		if (this.eventNaming == "default") {
			for (var eventName in this.eventNames) {
				this.eventNames[eventName] = this.widgetId+"/"+eventName;
			}
		}
	},

	layoutItem: function(label_w, accel_w){

		var x_label = this.parent.itemHeight + this.parent.iconGap;
		var x_accel = x_label + label_w + this.parent.accelGap;
		var x_submu = x_accel + accel_w + this.parent.submenuGap;
		var total_w = x_submu + this.parent.submenuIconSize + this.parent.finalGap;


		this.iconNode.style.left = '0px';
		this.iconNode.style.top = '0px';


		if (this.iconSrc){

			if ((this.iconSrc.toLowerCase().substring(this.iconSrc.length-4) == ".png") && (dojo.render.html.ie)){

				this.iconNode.style.filter = "progid:DXImageTransform.Microsoft.AlphaImageLoader(src='"+this.iconSrc+"', sizingMethod='image')";
				this.iconNode.style.backgroundImage = '';
			}else{
				this.iconNode.style.backgroundImage = 'url('+this.iconSrc+')';
			}
		}else{
			this.iconNode.style.backgroundImage = '';
		}

		dojo.style.setOuterWidth(this.iconNode, this.parent.itemHeight);
		dojo.style.setOuterHeight(this.iconNode, this.parent.itemHeight);

		dojo.style.setOuterHeight(this.labelNode, this.parent.itemHeight);
		dojo.style.setOuterHeight(this.accelNode, this.parent.itemHeight);

		dojo.style.setContentWidth(this.domNode, total_w);
		dojo.style.setContentHeight(this.domNode, this.parent.itemHeight);

		this.labelNode.style.left = x_label + 'px';
		this.accelNode.style.left = x_accel + 'px';
		this.submenuNode.style.left = x_submu + 'px';

		dojo.style.setOuterWidth(this.submenuNode, this.parent.submenuIconSize);
		dojo.style.setOuterHeight(this.submenuNode, this.parent.itemHeight);

		this.submenuNode.style.display = this.submenuId ? 'block' : 'none';
		this.submenuNode.style.backgroundImage = 'url('+this.parent.submenuIconSrc+')';

		dojo.style.setOuterWidth(this.targetNode, total_w);
		dojo.style.setOuterHeight(this.targetNode, this.parent.itemHeight);
	},

	onHover: function(){

		if (this.is_hovering){ return; }
		if (this.is_open){ return; }

		this.parent.closeSubmenu();
		this.highlightItem();

		if (this.is_hovering){ this.stopSubmenuTimer(); }
		this.is_hovering = true;
		this.startSubmenuTimer();
	},

	onUnhover: function(){
		if (!this.is_open){ this.unhighlightItem(); }

		this.is_hovering = false;
		this.stopSubmenuTimer();
	},

	// Internal function for clicks
	_onClick: function(){
		if (this.disabled){ return; }

		if (this.submenuId){
			if (!this.is_open){
				this.stopSubmenuTimer();
				this.openSubmenu();
			}
		}else{
			this.parent.closeAll();
		}

		// for some browsers the onMouseOut doesn't get called (?), so call it manually
		this.onUnhover();

		// user defined handler for click
		this.onClick();

		dojo.event.topic.publish(this.eventNames.engage, this);
	},

	// User defined function to handle clicks
	onClick: function() { },

	highlightItem: function(){
		dojo.html.addClass(this.domNode, 'dojoMenuItem2Hover');
		this.submenuNode.style.backgroundImage = 'url('+this.parent.submenuIconOnSrc+')';
	},

	unhighlightItem: function(){
		dojo.html.removeClass(this.domNode, 'dojoMenuItem2Hover');
		this.submenuNode.style.backgroundImage = 'url('+this.parent.submenuIconSrc+')';
	},

	startSubmenuTimer: function(){
		this.stopSubmenuTimer();

		if (this.disabled){ return; }

		var self = this;
		var closure = function(){ return function(){ self.openSubmenu(); } }();

		this.hover_timer = window.setTimeout(closure, this.parent.submenuDelay);
	},

	stopSubmenuTimer: function(){
		if (this.hover_timer){
			window.clearTimeout(this.hover_timer);
			this.hover_timer = null;
		}
	},

	openSubmenu: function(){
		// first close any other open submenu
		this.parent.closeSubmenu();

		var submenu = dojo.widget.getWidgetById(this.submenuId);
		if (submenu){

			this.parent.openSubmenu(submenu, this);
		}

		//dojo.debug('open submenu for item '+this.widgetId);
	},

	closedSubmenu: function(){

		this.onUnhover();
	},

	setDisabled: function(value){
		this.disabled = value;

		if (this.disabled){
			dojo.html.addClass(this.domNode, 'dojoMenuItem2Disabled');
		}else{
			dojo.html.removeClass(this.domNode, 'dojoMenuItem2Disabled');
		}
	},

	getLabelWidth: function(){

		var node = this.labelNode.childNodes[0];

		return dojo.style.getOuterWidth(node);
	},

	getAccelWidth: function(){

		var node = this.accelNode.childNodes[0];

		return dojo.style.getOuterWidth(node);
	},

	menuOpen: function(message) {
	}

});


dojo.widget.MenuSeparator2 = function(){
	dojo.widget.HtmlWidget.call(this);
}

dojo.inherits(dojo.widget.MenuSeparator2, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.MenuSeparator2, {
	widgetType: "MenuSeparator2",

	domNode: null,
	topNode: null,
	bottomNode: null,

	templateString: '<div class="dojoMenuSeparator2">'
			+'<div dojoAttachPoint="topNode" class="dojoMenuSeparator2Top"></div>'
			+'<div dojoAttachPoint="bottomNode" class="dojoMenuSeparator2Bottom"></div>'
			+'</div>',

	postCreate: function(){
		dojo.html.disableSelection(this.domNode);
		this.layoutItem();
	},

	layoutItem: function(label_w, accel_w){

		var full_width = this.parent.itemHeight
				+ this.parent.iconGap
				+ label_w
				+ this.parent.accelGap
				+ accel_w
				+ this.parent.submenuGap
				+ this.parent.submenuIconSize
				+ this.parent.finalGap;

		if (isNaN(full_width)){ return; }

		dojo.style.setContentHeight(this.domNode, this.parent.separatorHeight);
		dojo.style.setContentWidth(this.domNode, full_width);
	}
});

//
// the menu manager makes sure we don't have several menus
// open at once. the root menu in an opening sequence calls
// opened(). when a root menu closes it calls closed(). then
// everything works. lovely.
//

dojo.widget.html.Menu2Manager = new function(){

	this.currentMenu = null;
	this.currentButton = null;		// button that opened current menu (if any)
	this.focusNode = null;

	dojo.event.connect(document, 'onmousedown', this, 'onClick');
	dojo.event.connect(window, "onscroll", this, "onClick");

	this.closed = function(menu){
		if (this.currentMenu == menu){
			this.currentMenu = null;
			this.currentButton = null;
		}
	};

	this.opened = function(menu, button){
		if (menu == this.currentMenu){ return; }

		if (this.currentMenu){
			this.currentMenu.close();
		}

		this.currentMenu = menu;
		this.currentButton = button;
	};

	this.onClick = function(e){

		if (!this.currentMenu){ return; }

		var scrolloffset = dojo.html.getScrollOffset();

		var x = e.clientX + scrolloffset[0];
		var y = e.clientY + scrolloffset[1];

		var m = this.currentMenu;

		// starting from the base menu, perform a hit test
		// and exit when one succeeds

		while (m){

			if (m.isPointInMenu(x, y)){

				return;
			}

			m = m.currentSubmenu;
		}

		// Also, if user clicked the button that opened this menu, then
		// that button will send the menu a close() command, so this code
		// shouldn't try to close the menu.  Closing twice messes up animation.
		if (this.currentButton && dojo.html.overElement(this.currentButton, e)){
			return;
		}

		// the click didn't fall within the open menu tree
		// so close it

		this.currentMenu.close();
	};
}

// ************************** make contextmenu work in konqueror and opera *********************
dojo.widget.Menu2.OperaAndKonqFixer = new function(){
 	var implement = true;
 	var delfunc = false;

 	/** 	dom event check
 	*
 	*	make a event and dispatch it and se if it calls function below,
 	*	if it does its supported and we dont need to implement our own
 	*/

 	// gets called if we have support for oncontextmenu
 	if (!dojo.lang.isFunction(document.oncontextmenu)){
 		document.oncontextmenu = function(){
 			implement = false;
 			delfunc = true;
 		}
 	}

 	if (document.createEvent){ // moz, safari has contextmenu event, need to do livecheck on this env.
 		try {
 			var e = document.createEvent("MouseEvents");
 			e.initMouseEvent("contextmenu", 1, 1, window, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, null);
 			document.dispatchEvent(e);
 		} catch (e) {/* assume not supported */}
 	} else {
 		// IE no need to implement custom contextmenu
 		implement = false;
 	}

 	// clear this one if it wasn't there before
 	if (delfunc){
 		delete document.oncontextmenu;
 	}
 	/***** end dom event check *****/


 	/**
 	*	this fixes a dom node by attaching a custom oncontextmenu function that gets called when apropriate
 	*	@param	node	a dom node
 	*
 	*	no returns
 	*/
 	this.fixNode = function(node){
 		if (implement){
 			// attach stub oncontextmenu function
 			if (!dojo.lang.isFunction(node.oncontextmenu)){
 				node.oncontextmenu = function(e){/*stub*/}
 			}

 			// attach control function for oncontextmenu
 			if (window.opera){
 				// opera
 				// listen to ctrl-click events
 				node._menufixer_opera = function(e){
 					if (e.ctrlKey){
 						this.oncontextmenu(e);
 					}
 				};

 				dojo.event.connect(node, "onclick", node, "_menufixer_opera");

 			} else {
 				// konqueror
 				// rightclick, listen to mousedown events
 				node._menufixer_konq = function(e){
 					if (e.button==2 ){
 						e.preventDefault(); // need to prevent browsers menu
 						this.oncontextmenu(e);
 					}
 				};

 				dojo.event.connect(node, "onmousedown", node, "_menufixer_konq");
 			}
 		}
 	}

 	/**
 	*	this cleans up a fixed node, prevent memoryleak?
 	*	@param node	node to clean
 	*
 	*	no returns
 	*/
 	this.cleanNode = function(node){
 		if (implement){
 			// checks needed if we gets a non fixed node
 			if (node._menufixer_opera){
 				dojo.event.disconnect(node, "onclick", node, "_menufixer_opera");
 				delete node._menufixer_opera;
 			} else if(node._menufixer_konq){
 				dojo.event.disconnect(node, "onmousedown", node, "_menufixer_konq");
 				delete node._menufixer_konq;
 			}
 			if (node.oncontextmenu){
 				delete node.oncontextmenu;
 			}
 		}
 	}
};


dojo.widget.MenuBar2 = function(){
	dojo.widget.HtmlWidget.call(this);
}

dojo.inherits(dojo.widget.MenuBar2, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.MenuBar2, {
	widgetType: "MenuBar2",
	isContainer: true,

	snarfChildDomOutput: true,

	currentItem: null,
	isExpanded: false,

	currentSubmenu: null,
	currentSubmenuTrigger: null,

	domNode: null,
	containerNode: null,

	templateString: '<div class="dojoMenuBar2"><div dojoAttachPoint="containerNode" class="dojoMenuBar2Client"></div></div>',
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlMenu2.css"),

	itemHeight: 18,
	openEvent: null,


	postCreate: function(){

		// do something here

		this.layoutMenuSoon();
	},

	layoutMenuSoon: function(){
		dojo.lang.setTimeout(this, "layoutMenu", 0);
	},

	layoutMenu: function(){

		// menu must be attached to DOM for size calculations to work

		var parent = this.domNode.parentNode;
		if (! parent || parent == undefined) {
			document.body.appendChild(this.domNode);
		}


		// determine menu height

		var max_label_h = 0;

		for(var i=0; i<this.children.length; i++){

			if (this.children[i].getLabelHeight){

				max_label_h = Math.max(max_label_h, this.children[i].getLabelHeight());
			}
		}

		if (isNaN(max_label_h)){
			// Browser needs some more time to calculate sizes
			this.layoutMenuSoon();
			return;
		}

		var clientLeft = dojo.style.getPixelValue(this.domNode, "padding-left", true)
				+ dojo.style.getPixelValue(this.containerNode, "margin-left", true)
				+ dojo.style.getPixelValue(this.containerNode, "padding-left", true);
		var clientTop  = dojo.style.getPixelValue(this.domNode, "padding-top", true)
				+ dojo.style.getPixelValue(this.containerNode, "padding-top", true);

		if (isNaN(clientLeft) || isNaN(clientTop)){
			// Browser needs some more time to calculate sizes
			this.layoutMenuSoon();
			return;
		}

		var max_item_height = 0;
		var x = clientLeft;

		for (var i=0; i<this.children.length; i++){

			var ch = this.children[i];

			ch.layoutItem(max_label_h);

			ch.leftPosition = x;
			ch.domNode.style.left = x + 'px';

			x += dojo.style.getOuterWidth(ch.domNode);
			max_item_height = Math.max(max_item_height, dojo.style.getOuterHeight(ch.domNode));
		}

		dojo.style.setContentHeight(this.containerNode, max_item_height);
		dojo.style.setContentHeight(this.domNode, dojo.style.getOuterHeight(this.containerNode));
	},

	openSubmenu: function(submenu, from_item){

		var our_pos = dojo.style.getAbsolutePosition(this.domNode, false);

		var our_h = dojo.style.getOuterHeight(this.domNode);
		var item_x = from_item.leftPosition;

		var x = our_pos.x + item_x;
		var y = our_pos.y + our_h;

		this.currentSubmenu = submenu;
		this.currentSubmenu.open(x, y, this, from_item.domNode);
		this.currentSubmenu.parentMenuBar = this;
	},

	closeSubmenu: function(){

		if (this.currentSubmenu == null){ return; }

		var menu = this.currentSubmenu;
		this.currentSubmenu = null;
		menu.close();
	},

	itemHover: function(item){

		if (item == this.currentItem) return;

		if (this.currentItem){
			this.currentItem.unhighlightItem();

			if (this.isExpanded){
				this.closeSubmenu();
			}
		}

		this.currentItem = item;
		this.currentItem.highlightItem();

		if (this.isExpanded){
			this.currentItem.expandMenu();
		}
	},

	itemUnhover: function(item){

		if (item != this.currentItem) return;

		if (this.currentItem && !this.isExpanded){
			this.currentItem.unhighlightItem();
			this.currentItem = null;
		}
	},

	itemClick: function(item){

		if (item != this.currentItem){

			this.itemHover(item);
		}

		if (this.isExpanded){

			this.isExpanded = false;
			this.closeSubmenu();

		}else{

			this.isExpanded = true;
			this.currentItem.expandMenu();
		}
	},

	closedMenu: function(menu){

		if (this.currentSubmenu == menu){

			this.isExpanded = false;
			this.itemUnhover(this.currentItem);
		}
	}
});


dojo.widget.MenuBarItem2 = function(){
	dojo.widget.HtmlWidget.call(this);
}

dojo.inherits(dojo.widget.MenuBarItem2, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.MenuBarItem2, {

	widgetType: "MenuBarItem2",
	templateString:
			 '<div class="dojoMenuBarItem2">'
			+'<span dojoAttachPoint="labelNode" class="dojoMenuBarItem2Label"><span><span></span></span></span>'
			+'<div dojoAttachPoint="targetNode" class="dojoMenuBarItem2Target" dojoAttachEvent="onMouseOver: onHover; onMouseOut: onUnhover; onClick: _onClick;">&nbsp;</div>'
			+'</div>',

	//
	// nodes
	//

	domNode: null,
	labelNode: null,
	targetNode: null,

	//
	// internal settings
	//

	is_hovering: false,
	hover_timer: null,
	is_open: false,

	//
	// options
	//

	caption: 'Untitled',
	accelKey: '',
	iconSrc: '',
	submenuId: '',
	disabled: false,
	eventNaming: "default",


	postCreate: function(){

		dojo.html.disableSelection(this.domNode);

		if (this.disabled){
			this.setDisabled(true);
		}

		this.labelNode.childNodes[0].appendChild(document.createTextNode(this.caption));

		this.labelShadowNode = this.labelNode.childNodes[0].childNodes[0];
		this.labelShadowNode.appendChild(document.createTextNode(this.caption));

		if (this.eventNaming == "default") {
			for (var eventName in this.eventNames) {
				this.eventNames[eventName] = this.widgetId+"/"+eventName;
			}
		}
	},

	layoutItem: function(item_h){

		var label_w = dojo.style.getOuterWidth(this.labelNode);

		var clientLeft = dojo.style.getPixelValue(this.domNode, "padding-left", true);
		var clientTop  = dojo.style.getPixelValue(this.domNode, "padding-top", true);

		this.labelNode.style.left = clientLeft + 'px';

		dojo.style.setOuterHeight(this.labelNode, item_h);
		dojo.style.setContentWidth(this.domNode, label_w);
		dojo.style.setContentHeight(this.domNode, item_h);

		this.labelNode.style.left = '0px';

		dojo.style.setOuterWidth(this.targetNode, label_w);
		dojo.style.setOuterHeight(this.targetNode, item_h);
	},

	getLabelHeight: function(){

		return dojo.style.getOuterHeight(this.labelNode);
	},

	onHover: function(){
		this.parent.itemHover(this);
	},

	onUnhover: function(){
		this.parent.itemUnhover(this);
	},

	_onClick: function(){
		this.parent.itemClick(this);
	},

	highlightItem: function(){
		dojo.html.addClass(this.domNode, 'dojoMenuBarItem2Hover');
	},

	unhighlightItem: function(){
		dojo.html.removeClass(this.domNode, 'dojoMenuBarItem2Hover');
	},

	expandMenu: function(){

		var submenu = dojo.widget.getWidgetById(this.submenuId);
		if (submenu){

			this.parent.openSubmenu(submenu, this);
		}
	},

	setDisabled: function(value){
		this.disabled = value;

		if (this.disabled){
			dojo.html.addClass(this.domNode, 'dojoMenuBarItem2Disabled');
		}else{
			dojo.html.removeClass(this.domNode, 'dojoMenuBarItem2Disabled');
		}
	}
});

// make it a tag
dojo.widget.tags.addParseTreeHandler("dojo:MenuBar2");
dojo.widget.tags.addParseTreeHandler("dojo:MenuBarItem2");
dojo.widget.tags.addParseTreeHandler("dojo:PopupMenu2");
dojo.widget.tags.addParseTreeHandler("dojo:MenuItem2");
dojo.widget.tags.addParseTreeHandler("dojo:MenuSeparator2");

