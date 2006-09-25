/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/* TODO:
 * - make the dropdowns "smart" so they can't get cutoff on bottom of page, sides of page, etc.
 * - unify menus with the MenuItem and Menu classes so we can add stuff to all menus at once
 * - allow buttons to be enabled/disabled at runtime
 *     - this probably means creating all menus upfront and then triggering a disable action
 *       for disabled buttons in the constructor loop. we'll need a disable and enable action anyway
 * - should each button with menu be a widget object of it's own?
 */
dojo.provide("dojo.widget.SimpleDropdownButtons");
dojo.provide("dojo.widget.HtmlSimpleDropdownButtons");

dojo.deprecated("dojo.widget.SimpleDropdownButtons",  "use dojo.widget.DropDownButton", "0.4");

dojo.require("dojo.event.*");
dojo.require("dojo.widget.*");
dojo.require("dojo.uri.Uri");
dojo.require("dojo.dom");
dojo.require("dojo.style");
dojo.require("dojo.html");

dojo.widget.tags.addParseTreeHandler("dojo:simpledropdownbuttons");

dojo.widget.HtmlSimpleDropdownButtons = function() {
	dojo.widget.HtmlWidget.call(this);

	this.widgetType = "SimpleDropdownButtons";
	this.templateCssPath = dojo.uri.dojoUri("src/widget/templates/HtmlSimpleDropdownButtons.css");

	this.menuTriggerClass = "dojoSimpleDropdownButtons";
	this.menuClass = "dojoSimpleDropdownButtonsMenu";

	// overwrite buildRendering so we don't clobber our list
	this.buildRendering = function(args, frag) {
		if(this.templateCssPath) {
			dojo.style.insertCssFile(this.templateCssPath, null, true);
		}
		this.domNode = frag["dojo:"+this.widgetType.toLowerCase()]["nodeRef"];

		var menu = this.domNode;
		if( !dojo.html.hasClass(menu, this.menuTriggerClass) ) {
			dojo.html.addClass(menu, this.menuTriggerClass);
		}
		var li = dojo.dom.getFirstChildElement(menu);
		var menuIDs = [];
		var arrowIDs = [];

		while(li) {
			if(li.getElementsByTagName("ul").length > 0) {
				var a = dojo.dom.getFirstChildElement(li);
				var arrow = document.createElement("a");
				arrow.href = "javascript:;";
				arrow.innerHTML = "&nbsp;";
				dojo.html.setClass(arrow, "downArrow");
				if(!arrow.id) {
					arrow.id = dojo.dom.getUniqueId();
				}
				arrowIDs.push(arrow.id);
				var submenu = dojo.dom.getNextSiblingElement(a);
				if(!submenu.id) {
					submenu.id = dojo.dom.getUniqueId();
				}
				menuIDs.push(submenu.id);

				if( dojo.html.hasClass(a, "disabled") ) {
					dojo.html.addClass(arrow, "disabled");
					dojo.html.disableSelection(li);
					arrow.onfocus = function(){ this.blur(); }
				} else {
					dojo.html.addClass(submenu, this.menuClass);
					document.body.appendChild(submenu);
					dojo.event.connect(arrow, "onmousedown", (function() {
						var ar = arrow;
						return function(e) {
							dojo.html.addClass(ar, "pressed");
						}
					})());
					dojo.event.connect(arrow, "onclick", (function() {
						var aa = a;
						var ar = arrow;
						var sm = submenu;
						var setWidth = false;

						return function(e) {
							hideAll(sm, ar);
							sm.style.left = (dojo.html.getScrollLeft()
								+ e.clientX - e.layerX + aa.offsetLeft) + "px";
							sm.style.top = (dojo.html.getScrollTop() + e.clientY
								- e.layerY + aa.offsetTop + aa.offsetHeight) + "px";
							sm.style.display = sm.style.display == "block" ? "none" : "block";
							if(sm.style.display == "none") {
								dojo.html.removeClass(ar, "pressed");
								e.target.blur()
							}
							if(!setWidth && sm.style.display == "block"
								&& sm.offsetWidth < aa.offsetWidth + ar.offsetWidth) {
								sm.style.width = aa.offsetWidth + ar.offsetWidth + "px";
								setWidth = true;
							}
							e.preventDefault();
						}
					})());
				}

				dojo.event.connect(a, "onclick", function(e) {
					if(e && e.target && e.target.blur) {
						e.target.blur();
					}
				});

				if(a.nextSibling) {
					li.insertBefore(arrow, a.nextSibling);
				} else {
					li.appendChild(arrow);
				}

			}
			li = dojo.dom.getNextSiblingElement(li);
		}

		function hideAll(excludeMenu, excludeArrow) {
			// hide menus
			for(var i = 0; i < menuIDs.length; i++) {
				var m = document.getElementById(menuIDs[i]);
				if(!excludeMenu || m != excludeMenu) {
					document.getElementById(menuIDs[i]).style.display = "none";
				}
			}
			// restore arrows to non-pressed state
			for(var i = 0; i < arrowIDs.length; i++) {
				var m = document.getElementById(arrowIDs[i]);
				if(!excludeArrow || m != excludeArrow) {
					dojo.html.removeClass(m, "pressed");
				}
			}
		}

		dojo.event.connect(document.documentElement, "onmousedown", function(e) {
			if( dojo.html.hasClass(e.target, "downArrow") ) { return };
			for(var i = 0; i < menuIDs.length; i++) {
				if( dojo.dom.isDescendantOf(e.target, document.getElementById(menuIDs[i])) ) {
					return;
				}
			}
			hideAll();
		});
	}
}
dojo.inherits(dojo.widget.HtmlSimpleDropdownButtons, dojo.widget.HtmlWidget);
