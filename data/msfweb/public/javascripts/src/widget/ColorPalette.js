/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.ColorPalette");
dojo.provide("dojo.widget.html.ColorPalette");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.Toolbar");
dojo.require("dojo.html");

dojo.widget.tags.addParseTreeHandler("dojo:ToolbarColorDialog");

dojo.widget.html.ToolbarColorDialog = function(){
	dojo.widget.html.ToolbarDialog.call(this);
	
	/*
	FIXME: 	why the fuck did anyone ever think this kind of expensive iteration
			was a good idea?

	for (var method in this.constructor.prototype) {
		this[method] = this.constructor.prototype[method];
	}
	*/
}

dojo.inherits(dojo.widget.html.ToolbarColorDialog, dojo.widget.html.ToolbarDialog);

dojo.lang.extend(dojo.widget.html.ToolbarColorDialog, {

	widgetType: "ToolbarColorDialog",

	palette: "7x10",

	fillInTemplate: function (args, frag) {
		dojo.widget.html.ToolbarColorDialog.superclass.fillInTemplate.call(this, args, frag);
		this.dialog = dojo.widget.createWidget("ColorPalette", {palette: this.palette});
		this.dialog.domNode.style.position = "absolute";

		dojo.event.connect(this.dialog, "onColorSelect", this, "_setValue");
	},

	_setValue: function(color) {
		this._value = color;
		this._fireEvent("onSetValue", color);
	},
	
	showDialog: function (e) {
		dojo.widget.html.ToolbarColorDialog.superclass.showDialog.call(this, e);
		var x = dojo.html.getAbsoluteX(this.domNode);
		var y = dojo.html.getAbsoluteY(this.domNode) + dojo.html.getInnerHeight(this.domNode);
		this.dialog.showAt(x, y);
	},
	
	hideDialog: function (e) {
		dojo.widget.html.ToolbarColorDialog.superclass.hideDialog.call(this, e);
		this.dialog.hide();
	}
});



dojo.widget.tags.addParseTreeHandler("dojo:colorpalette");

dojo.widget.html.ColorPalette = function () {
	dojo.widget.HtmlWidget.call(this);
}

dojo.inherits(dojo.widget.html.ColorPalette, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.html.ColorPalette, {

	widgetType: "colorpalette",
	
	palette: "7x10",

	bgIframe: null,
	
	palettes: {
		"7x10": [["fff", "fcc", "fc9", "ff9", "ffc", "9f9", "9ff", "cff", "ccf", "fcf"],
			["ccc", "f66", "f96", "ff6", "ff3", "6f9", "3ff", "6ff", "99f", "f9f"],
			["c0c0c0", "f00", "f90", "fc6", "ff0", "3f3", "6cc", "3cf", "66c", "c6c"],
			["999", "c00", "f60", "fc3", "fc0", "3c0", "0cc", "36f", "63f", "c3c"],
			["666", "900", "c60", "c93", "990", "090", "399", "33f", "60c", "939"],
			["333", "600", "930", "963", "660", "060", "366", "009", "339", "636"],
			["000", "300", "630", "633", "330", "030", "033", "006", "309", "303"]],
	
		"3x4": [["ffffff"/*white*/, "00ff00"/*lime*/, "008000"/*green*/, "0000ff"/*blue*/],
			["c0c0c0"/*silver*/, "ffff00"/*yellow*/, "ff00ff"/*fuchsia*/, "000080"/*navy*/],
			["808080"/*gray*/, "ff0000"/*red*/, "800080"/*purple*/, "000000"/*black*/]]
			//["00ffff"/*aqua*/, "808000"/*olive*/, "800000"/*maroon*/, "008080"/*teal*/]];
	},

	buildRendering: function () {
		
		this.domNode = document.createElement("table");
		dojo.html.disableSelection(this.domNode);
		dojo.event.connect(this.domNode, "onmousedown", function (e) {
			e.preventDefault();
		});
		with (this.domNode) { // set the table's properties
			cellPadding = "0"; cellSpacing = "1"; border = "1";
			style.backgroundColor = "white"; //style.position = "absolute";
		}
		var tbody = document.createElement("tbody");
		this.domNode.appendChild(tbody);
		var colors = this.palettes[this.palette];
		for (var i = 0; i < colors.length; i++) {
			var tr = document.createElement("tr");
			for (var j = 0; j < colors[i].length; j++) {
				if (colors[i][j].length == 3) {
					colors[i][j] = colors[i][j].replace(/(.)(.)(.)/, "$1$1$2$2$3$3");
				}
	
				var td = document.createElement("td");
				with (td.style) {
					backgroundColor = "#" + colors[i][j];
					border = "1px solid gray";
					width = height = "15px";
					fontSize = "1px";
				}
	
				td.color = "#" + colors[i][j];
	
				td.onmouseover = function (e) { this.style.borderColor = "white"; }
				td.onmouseout = function (e) { this.style.borderColor = "gray"; }
				dojo.event.connect(td, "onmousedown", this, "click");
	
				td.innerHTML = "&nbsp;";
				tr.appendChild(td);
			}
			tbody.appendChild(tr);
		}

		if(dojo.render.html.ie){
			this.bgIframe = document.createElement("<iframe frameborder='0' src='javascript:void(0);'>");
			with(this.bgIframe.style){
				position = "absolute";
				left = top = "0px";
				display = "none";
			}
			document.body.appendChild(this.bgIframe);
			dojo.style.setOpacity(this.bgIframe, 0);
		}
	},

	click: function (e) {
		this.onColorSelect(e.currentTarget.color);
		e.currentTarget.style.borderColor = "gray";
	},

	onColorSelect: function (color) { },

	hide: function (){
		this.domNode.parentNode.removeChild(this.domNode);
		if(this.bgIframe){
			this.bgIframe.style.display = "none";
		}
	},
	
	showAt: function (x, y) {
		with(this.domNode.style){
			top = y + "px";
			left = x + "px";
			zIndex = 999;
		}
		document.body.appendChild(this.domNode);
		if(this.bgIframe){
			with(this.bgIframe.style){
				display = "block";
				top = y + "px";
				left = x + "px";
				zIndex = 998;
				width = dojo.html.getOuterWidth(this.domNode) + "px";
				height = dojo.html.getOuterHeight(this.domNode) + "px";
			}

		}
	}

});
