/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.Spinner");
dojo.require("dojo.widget.Spinner");
dojo.require("dojo.widget.Manager.*");
dojo.require("dojo.widget.*");
dojo.require("dojo.io.*");
dojo.require("dojo.lfx.*");
dojo.require("dojo.dom");
dojo.require("dojo.html");
dojo.require("dojo.string");
dojo.require("dojo.widget.html.stabile");

dojo.widget.html.Spinner = function(){
	dojo.widget.Spinner.call(this);
	dojo.widget.HtmlWidget.call(this);
}

dojo.inherits(dojo.widget.html.Spinner, dojo.widget.HtmlWidget);

// copied from superclass since we can't really over-ride via prototype
dojo.lang.extend(dojo.widget.html.Spinner, dojo.widget.Spinner.defaults);

dojo.lang.extend(dojo.widget.html.Spinner, {

	name: "", // clone in the name from the DOM node
	inputNode: null,
	upArrowNode: null,
	downArrowNode: null,
	absNode: null,
	relNode: null,
	innerRelNode: null,
	spacerNode: null,
	inputWidgetId: "",
	inputWidget: null,
	typamaticTimer: null,
	typamaticFunction: null,
	defaultTimeout: 500,
	currentTimeout: this.defaultTimeout,
	eventCount: 0,

	templatePath: dojo.uri.dojoUri("src/widget/templates/HtmlSpinner.html"),
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlSpinner.css"),

	setValue: function(value){
		this.inputWidget.setValue(value);
		this.inputWidget.adjustValue(0);
		dojo.widget.html.stabile.setState(this.widgetId, this.getState(), true);
	},

	getValue: function(){
		return this.inputWidget.getValue();
	},

	getState: function(){
		return {value: this.getValue()};
	},

	setState: function(state){
		this.setValue(state.value);
	},

	// does the keyboard related stuff
	_handleKeyEvents: function(evt){
		var k = dojo.event.browser.keys;
		var keyCode = evt.keyCode;

		switch(keyCode){
 			case k.KEY_DOWN_ARROW:
				dojo.event.browser.stopEvent(evt);
				this.downArrowPressed(evt);
				return;
			case k.KEY_UP_ARROW:
				dojo.event.browser.stopEvent(evt);
				this.upArrowPressed(evt);
				return;
		}
		this.eventCount++;

	},

	onKeyDown: function(evt){
		// IE needs to stop keyDown others need to stop keyPress
		if(!document.createEvent){ // only IE
			this._handleKeyEvents(evt);
		}
	},

	onKeyPress: function(evt){
		if(document.createEvent){ // never IE
			this._handleKeyEvents(evt);
		}
	},

	fillInTemplate: function(args, frag){
		var source = this.getFragNodeRef(frag);
		dojo.html.copyStyle(this.domNode, source);
	},


	resizeUpArrow: function(){
		var newh = dojo.style.getContentBoxHeight(this.inputNode) >> 1;
		if(newh==0){
			// need more time to calculate size
			dojo.lang.setTimeout(this, "resizeUpArrow", 100);
			return;
		}
		var oldh = this.upArrowNode.height;
		if(oldh==0){
			// need more time to calculate size
			dojo.lang.setTimeout(this, "resizeUpArrow", 100);
			return;
		}
		var ratio = newh / oldh;
		this.upArrowNode.width=Math.floor(this.upArrowNode.width * ratio);
		this.upArrowNode.height=newh;
	},

	resizeDownArrow: function(){
		var newh = dojo.style.getContentBoxHeight(this.inputNode) >> 1;
		if(newh==0){
			// need more time to calculate size
			dojo.lang.setTimeout(this, "resizeDownArrow", 100);
			return;
		}
		var oldh = this.downArrowNode.height;
		if(oldh==0){
			// need more time to calculate size
			dojo.lang.setTimeout(this, "resizeDownArrow", 100);
			return;
		}
		var ratio = newh / oldh;
		this.downArrowNode.width=Math.floor(this.downArrowNode.width * ratio);
		this.downArrowNode.height=newh;
	},

	resizeSpacer: function(){
		var newh = dojo.style.getContentBoxHeight(this.inputNode) >> 1;
		if( newh==0 ){
			// need more time to calculate size
			dojo.lang.setTimeout(this, "resizeSpacer", 100);
			return;
		}
		var oldh = this.downArrowNode.height;
		if( oldh==0 ){
			// need more time to calculate size
			dojo.lang.setTimeout(this, "resizeSpacer", 100);
			return;
		}
		var ratio = newh / oldh;
		this.spacerNode.width=Math.floor(this.spacerNode.width * ratio);
		this.spacerNode.height=newh;
	},

	_pressButton: function(node){
		with(node.style){
			borderRight = "0px";
			borderBottom = "0px";
			borderLeft = "1px solid black";
			borderTop = "1px solid black";
		}
	},

	_releaseButton: function(node){
		with(node.style){
			borderLeft = "0px";
			borderTop = "0px";
			borderRight = "1px solid gray";
			borderBottom = "1px solid gray";
		}
	},

	downArrowPressed: function(evt){
		if(typeof evt != "number"){
		    if(this.typamaticTimer != null){
				if(this.typamaticFunction == this.downArrowPressed){
					return;
				}
		        clearTimeout(this.typamaticTimer);
		    }
		    this._releaseButton(this.upArrowNode);
		    this.eventCount++;
		    this.typamaticTimer = null;
		    this.currentTimeout = this.defaultTimeout;

		}else if (evt != this.eventCount){
		    this._releaseButton(this.downArrowNode);
		    return;
		}
		this._pressButton(this.downArrowNode);
		this.setCursorX(this.inputWidget.adjustValue(-1,this.getCursorX()));
		this.typamaticFunction = this.downArrowPressed;
		this.typamaticTimer = setTimeout( dojo.lang.hitch(this,function(){this.downArrowPressed(this.eventCount);}), this.currentTimeout);
		this.currentTimeout = Math.round(this.currentTimeout * 90 / 100);
	},

	upArrowPressed: function(evt){
		if(typeof evt != "number"){
		    if(this.typamaticTimer != null){
				if(this.typamaticFunction == this.upArrowPressed){
					return;
				}
		        clearTimeout(this.typamaticTimer);
		    }
		    this._releaseButton(this.downArrowNode);
		    this.eventCount++;
		    this.typamaticTimer = null;
		    this.currentTimeout = this.defaultTimeout;
		}else if(evt != this.eventCount) {
		    this._releaseButton(this.upArrowNode);
		    return;
		}
		this._pressButton(this.upArrowNode);
		this.setCursorX(this.inputWidget.adjustValue(+1,this.getCursorX()));
		this.typamaticFunction = this.upArrowPressed;
		this.typamaticTimer = setTimeout( dojo.lang.hitch(this,function(){this.upArrowPressed(this.eventCount);}), this.currentTimeout);
		this.currentTimeout = Math.round(this.currentTimeout * 90 / 100);
	},

	arrowReleased: function(evt){
		this.inputNode.focus();
		if(evt.keyCode && evt.keyCode != null){
			var keyCode = evt.keyCode;
			var k = dojo.event.browser.keys;

			switch(keyCode){
				case k.KEY_DOWN_ARROW:
				case k.KEY_UP_ARROW:
					dojo.event.browser.stopEvent(evt);
					break;
			}
		}
		this._releaseButton(this.upArrowNode);
		this._releaseButton(this.downArrowNode);
		this.eventCount++;
		if(this.typamaticTimer != null){
		    clearTimeout(this.typamaticTimer);
		}
		this.typamaticTimer = null;
		this.currentTimeout = this.defaultTimeout;
	},

	mouseWheeled: function(evt) {
		var scrollAmount = 0;
		if(typeof evt.wheelDelta == 'number'){ // IE
		    scrollAmount = evt.wheelDelta;
		}else if (typeof evt.detail == 'number'){ // Mozilla+Firefox
		    scrollAmount = -evt.detail;
		}
		if(scrollAmount > 0){
		    this.upArrowPressed(evt);
		    this.arrowReleased(evt);
		}else if (scrollAmount < 0){
		    this.downArrowPressed(evt);
		    this.arrowReleased(evt);
		}
	},

	getCursorX: function(){
		var x = -1;
		try{
		    this.inputNode.focus();
		    if (typeof this.inputNode.selectionEnd == "number"){
				x = this.inputNode.selectionEnd;
		    }else if (document.selection && document.selection.createRange) {
				var range = document.selection.createRange().duplicate();
				if(range.parentElement() == this.inputNode){
					range.moveStart('textedit', -1);
					x = range.text.length;
				}
		    }
		}catch(e){ /* squelch! */ }
		return x;
	},

	setCursorX: function(x){
		try{
			this.inputNode.focus();
		    if(!x){ x = 0 }
		    if(typeof this.inputNode.selectionEnd == "number"){
		        this.inputNode.selectionEnd = x;
		    }else if(this.inputNode.createTextRange){
		        var range = this.inputNode.createTextRange();
		        range.collapse(true);
		        range.moveEnd('character', x);
		        range.moveStart('character', x);
		        range.select();
		    }
		}catch(e){ /* squelch! */ }
	},

	postCreate: function(){
		this.domNode.style.display="none";

		if((typeof this.inputWidgetId != 'string')||(this.inputWidgetId.length == 0)){
		    var w=dojo.widget.manager.getAllWidgets();
		    for(var i=w.length-1; i>=0; i--){
		        if(w[i].adjustValue){
					this.inputWidget = w[i];
					break;
		        }
		    }
		}else{
		    this.inputWidget = dojo.widget.getWidgetById(this.inputWidgetId);
		}

		if(typeof this.inputWidget != 'object'){
			dojo.lang.setTimeout(this, "postCreate", 100); 
			return;
		}
		var widgetNode = this.inputWidget.domNode;
		var inputNodes = widgetNode.getElementsByTagName('INPUT');
		this.inputNode = inputNodes[0];

		/*
		// unlink existing dom nodes from domNode
		this.downArrowNode = dojo.dom.removeNode(this.downArrowNode);
		this.upArrowNode = dojo.dom.removeNode(this.upArrowNode);
		this.spacerNode = dojo.dom.removeNode(this.spacerNode);
		this.innerRelNode = dojo.dom.removeNode(this.innerRelNode);
		this.absNode = dojo.dom.removeNode(this.absNode);
		this.relNode = dojo.dom.removeNode(this.relNode);
		*/

		// create a disconnected node
		this.innerRelNode.appendChild(this.upArrowNode);
		this.innerRelNode.appendChild(this.downArrowNode);
		this.absNode.appendChild(this.innerRelNode);
		this.relNode.appendChild(this.absNode);
		this.relNode.appendChild(this.spacerNode);

		dojo.event.connect(this.inputNode, "onkeypress", this, "onKeyPress");
		dojo.event.connect(this.inputNode, "onkeydown", this, "onKeyDown");
		dojo.event.connect(this.inputNode, "onkeyup", this, "arrowReleased");
		dojo.event.connect(this.downArrowNode, "onmousedown", this, "downArrowPressed");
		dojo.event.connect(this.downArrowNode, "onmouseup", this, "arrowReleased");
		dojo.event.connect(this.upArrowNode, "onmousedown", this, "upArrowPressed");
		dojo.event.connect(this.upArrowNode, "onmouseup", this, "arrowReleased");
		if(this.inputNode.addEventListener){
			// FIXME: why not use dojo.event.connect() to DOMMouseScroll here?
		    this.inputNode.addEventListener('DOMMouseScroll', dojo.lang.hitch(this, "mouseWheeled"), false); // Mozilla + Firefox + Netscape
		}else{
		    dojo.event.connect(this.inputNode, "onmousewheel", this, "mouseWheeled"); // IE + Safari
		}

		this.resizeDownArrow();
		this.resizeUpArrow();
		this.resizeSpacer();

		// make sure the disconnected node will fit right next to the INPUT tag w/o any interference
		dojo.html.copyStyle(this.relNode, this.inputNode);
		with(this.relNode.style){
			display = "inline";
			position = "relative";
			backgroundColor = "";
			marginLeft = "-1px";
			paddingLeft = "0";
		}
		this.inputNode.style.marginRight = "0px";
		this.inputNode.style.paddingRight = "0px";

		// add the disconnected node right after the INPUT tag
		dojo.dom.insertAfter(this.relNode, this.inputNode, false);
		this.domNode = dojo.dom.removeNode(this.domNode);
		// realign the spinner vertically in case there's a slight difference
		var absOffset = dojo.html.getAbsoluteY(this.relNode,true)-dojo.html.getAbsoluteY(this.absNode,true);
		this.absNode.style.top = absOffset-dojo.style.getBorderExtent(this.inputNode, "top")+"px";

		var s = dojo.widget.html.stabile.getState(this.widgetId);
		this.setValue(this.getValue());
		if(s){
			this.setState(s);
		}
	}
});
