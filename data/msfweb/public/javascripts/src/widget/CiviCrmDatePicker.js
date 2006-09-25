/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.CiviCrmDatePicker");
dojo.provide("dojo.widget.HtmlCiviCrmDatePicker");
dojo.require("dojo.widget.*");
dojo.require("dojo.event.*");
dojo.require("dojo.widget.DatePicker");
dojo.require("dojo.widget.html.DatePicker");
dojo.require("dojo.widget.html.TimePicker");
dojo.require("dojo.html");

dojo.widget.HtmlCiviCrmDatePicker = function(){
	this.widgetType = "CiviCrmDatePicker";
	this.idPrefix = "scheduled_date_time";
	this.mode = "datetime"; // can also be date or time

	this.datePicker = null;
	this.timePicker = null;

	// html nodes
	this.dateHolderTd = null;
	this.timeHolderTd = null;
	this.formItemsTd = null;
	this.formItemsTr = null;

	this.monthSelect = null;
	this.daySelect = null;
	this.yearSelect = null;
	this.hourSelect = null;
	this.minSelect = null;
	this.apSelect = null;

	this.templatePath = dojo.uri.dojoUri("src/widget/templates/HtmlCiviCrmDatePicker.html");

	this.modeFormats = {
		date: "MdY",
		time: "hiA"
	};

	this.formatMappings = {
		"M": "monthSelect",
		"d": "daySelect",
		"Y": "yearSelect",
		"h": "hourSelect",
		"i": "minSelect",
		"A": "apSelect"
	};

	this.setDateSelects = function(){
		var dateObj = this.datePicker.date;
		this.monthSelect.value = new String(dateObj.getMonth()+1);
		this.daySelect.value = new String(dateObj.getDate());
		this.yearSelect.value = new String(dateObj.getFullYear());
	}

	this.setTimeSelects = function(){
		var st = this.timePicker.selectedTime;
		this.hourSelect.value = new String(st.hour);
		this.minSelect.value = new String(st.minute);
		this.apSelect.value = st.amPm.toUpperCase();
	}

	this.fillInTemplate = function(args, frag){
		var nr = frag["dojo:"+this.widgetType.toLowerCase()]["nodeRef"];
		var sref = {};
		while(nr.firstChild){
			if(nr.firstChild.name){
				sref[nr.firstChild.name] = nr.firstChild;
			}
			this.formItemsTd.appendChild(nr.firstChild);
		}

		if(this.mode.indexOf("date") != -1){
			this.datePicker = dojo.widget.createWidget("DatePicker", {}, this.dateHolderTd);
			dojo.event.connect(	this.datePicker, "onSetDate", 
								this, "setDateSelects");

			var mfd = this.modeFormats.date;
			for(var x=0; x<mfd.length; x++){
				this[this.formatMappings[mfd[x]]] = sref[this.idPrefix+"["+mfd[x]+"]"];
			}
		}
		if(this.mode.indexOf("time") != -1){
			this.timePicker = dojo.widget.createWidget("TimePicker", {}, this.timeHolderTd);
			dojo.event.connect(	this.timePicker, "onSetTime", 
								this, "setTimeSelects");
			var mfd = this.modeFormats.time;
			for(var x=0; x<mfd.length; x++){
				this[this.formatMappings[mfd[x]]] = sref[this.idPrefix+"["+mfd[x]+"]"];
			}
		}
	}

	this.unhide = function(){
		this.formItemsTr.style.display = "";
	}

	this.postCreate = function(){
		dojo.event.kwConnect({
			type: "before", 
			srcObj: dojo.html.getParentByType(this.domNode, "form"),
			srcFunc: "onsubmit", 
			targetObj: this,
			targetFunc: "unhide"
		});
	}
}
dojo.inherits(dojo.widget.HtmlCiviCrmDatePicker, dojo.widget.HtmlWidget);
dojo.widget.tags.addParseTreeHandler("dojo:civicrmdatepicker");

