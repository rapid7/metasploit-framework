/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/* TODO:
 * - make the dropdown "smart" so it can't get cutoff on bottom of page, sides of page, etc.
 */

dojo.provide("dojo.widget.html.DropdownButton");

dojo.require("dojo.event.*");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.uri.Uri");
dojo.require("dojo.dom");
dojo.require("dojo.style");
dojo.require("dojo.html");

dojo.widget.html.DropdownButton = function() {
	// mix in the button properties
	dojo.widget.DropdownButton.call(this);
	dojo.widget.HtmlWidget.call(this);
}

dojo.inherits(dojo.widget.html.DropdownButton, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.html.DropdownButton, {
	
	// In IE, event handlers on objects inside buttons don't work correctly, so
	// we just set onClick on the button itself.
	templatePath: dojo.uri.dojoUri("src/widget/templates/HtmlDropDownButtonTemplate.html"),
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/HtmlButtonTemplate.css"),

	// attach points
	button: null,
	table: null,
	labelCell: null,
	borderCell: null,
	arrowCell: null,
	arrow: null,

	fillInTemplate: function(args, frag) {
		// input data (containing the anchor for the button itself, plus the
		// thing to display when you push the down arrow)
		var input = frag["dojo:"+this.widgetType.toLowerCase()]["nodeRef"];

		// Recursively expand widgets inside of the <dojo:dropdownButton>
		var parser = new dojo.xml.Parse();
		var frag = parser.parseElement(input, null, true);
		var ary = dojo.widget.getParser().createComponents(frag);

		this.a = dojo.dom.getFirstChildElement(input);	// the button contents
		this.menu = dojo.dom.getNextSiblingElement(this.a);	// the menu under the button
		
		this.disabled = dojo.html.hasClass(this.a, "disabled");
		if( this.disabled ) {
			dojo.html.addClass(this.button, "dojoDisabled");
			this.domNode.setAttribute("disabled", "true");
		}

		dojo.html.disableSelection(this.a);
		this.a.style["text-decoration"]="none";
		this.labelCell.appendChild(this.a);

		this.arrow.src =
			dojo.uri.dojoUri("src/widget/templates/images/dropdownButtonsArrow" +
			(this.disabled ? "-disabled" : "") + ".gif");

		// Attach menu to body so that it appears above other buttons
		this.menu.style.position="absolute";
		this.menu.style.display="none";
		this.menu.style["z-index"] = 99;
		document.body.appendChild(this.menu);
	},

	postCreate: function() {
		if ( dojo.render.html.ie ) {
			// Compensate for IE's weird padding of button content, which seems to be relative
			// to the length of the content
			var contentWidth = dojo.style.getOuterWidth(this.table);
			this.labelCell.style["left"] = "-" + (contentWidth / 10) + "px";
			this.arrowCell.style["left"] = (contentWidth / 10) + "px";
		}

		// Make menu at least as wide as the button
		var buttonWidth = dojo.style.getOuterWidth(this.button);
		var menuWidth = dojo.style.getOuterWidth(this.menu);
		if ( buttonWidth > menuWidth ) {
			dojo.style.setOuterWidth(this.menu, buttonWidth);
		}
	},

	// If someone clicks anywhere else on the screen (including another menu),
	// then close this menu.
	onCanvasMouseDown: function(e) {
		if( !dojo.dom.isDescendantOf(e.target, this.button) &&
			!dojo.dom.isDescendantOf(e.target, this.menu) ) {
			this.hideMenu();
		}
	},

	eventWasOverArrow: function(e) {
		// want to use dojo.html.overElement() but also need to detect clicks
		// on the area between the arrow and the edge of the button
		var eventX = e.clientX;
		var borderX = dojo.style.totalOffsetLeft(this.borderCell);
		return (eventX > borderX );
	},

	onMouseOver: function(e) {
		dojo.html.addClass(this.button, "dojoButtonHover");
		dojo.html.removeClass(this.button, "dojoButtonNoHover");
	},
	
	onMouseOut: function(e) {
		dojo.html.removeClass(this.button, "dojoButtonHover");
		dojo.html.addClass(this.button, "dojoButtonNoHover");
	},

	onClick: function(e) {
		if ( this.eventWasOverArrow(e) ) {
			this._onClickArrow();
		} else {
			this._onClickButton();
		}
	},

	// Action when the user presses the button
	_onClickButton: function(e) {
		if ( this.a ) {
			if ( this.a.click ) {
				this.a.click();
			} else if ( this.a.href ) {
				location.href = this.a.href;
			}
		}
	},

	// Action when user presses the arrow
	_onClickArrow: function() {
		if ( this.menu.style.display == "none" ) {
			this.showMenu();
		} else {
			this.hideMenu();
		}
	},
	
	showMenu: function() {
		if ( this.disabled )
			return;

		// Position it accordingly, relative to screen root (since
		// it's attached to document.body)
		this.menu.style.left = dojo.style.totalOffsetLeft(this.button) + "px";
		this.menu.style.top = dojo.style.totalOffsetTop(this.button) + dojo.style.getOuterHeight(this.button) + "px";

		// Display the menu; do this funky code below to stop the menu from extending
		// all the way to the right edge of the screen.
		// TODO: retest simple display="" to confirm that it doesn't work.
		try {
			this.menu.style.display="table";	// mozilla
		} catch(e) {
			this.menu.style.display="block";	// IE
		}

		// If someone clicks somewhere else on the screen then close the menu
		dojo.event.connect(document.documentElement, "onmousedown", this, "onCanvasMouseDown");
		
		// When someone clicks the menu, after the menu handles the event,
		// close the menu (be careful not to close the menu too early or else
		// the menu will never receive the event.)
		dojo.event.connect(this.menu, "onclick", this, "hideMenu");
	},

	hideMenu: function() {
		this.menu.style.display = "none";
		dojo.event.disconnect(document.documentElement, "onmousedown", this, "onCanvasMouseDown");
		dojo.event.disconnect(this.menu, "onclick", this, "hideMenu");
	}
});


