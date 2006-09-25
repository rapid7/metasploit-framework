/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.TimePicker");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.widget.TimePicker");
dojo.require("dojo.event.*");
dojo.require("dojo.date");
dojo.require("dojo.html");

dojo.widget.html.TimePicker = function(){
	dojo.widget.TimePicker.call(this);
	dojo.widget.HtmlWidget.call(this);


	var _this = this;
	// selected time, JS Date object
	this.time = "";
	// set following flag to true if a default time should be set
	this.useDefaultTime = false;
	// set the following to true to set default minutes to current time, false to // use zero
	this.useDefaultMinutes = false;
	// rfc 3339 date
	this.storedTime = "";
	// time currently selected in the UI, stored in hours, minutes, seconds in the format that will be actually displayed
	this.currentTime = {};
	this.classNames = {
		selectedTime: "selectedItem"
	}
	this.any = "any"
	// dom node indecies for selected hour, minute, amPm, and "any time option"
	this.selectedTime = {
		hour: "",
		minute: "",
		amPm: "",
		anyTime: false
	}

	// minutes are ordered as follows: ["12", "6", "1", "7", "2", "8", "3", "9", "4", "10", "5", "11"]
	this.hourIndexMap = ["", 2, 4, 6, 8, 10, 1, 3, 5, 7, 9, 11, 0];
	// minutes are ordered as follows: ["00", "30", "05", "35", "10", "40", "15", "45", "20", "50", "25", "55"]
	this.minuteIndexMap = [0, 2, 4, 6, 8, 10, 1, 3, 5, 7, 9, 11];

	this.templatePath =  dojo.uri.dojoUri("src/widget/templates/HtmlTimePicker.html");
	this.templateCssPath = dojo.uri.dojoUri("src/widget/templates/HtmlTimePicker.css");

	this.fillInTemplate = function(){
		this.initData();
		this.initUI();
	}

	this.initData = function() {
		// FIXME: doesn't currently validate the time before trying to set it
		// Determine the date/time from stored info, or by default don't 
		//  have a set time
		// FIXME: should normalize against whitespace on storedTime... for now 
		// just a lame hack
		if(this.storedTime.indexOf("T")!=-1 && this.storedTime.split("T")[1] && this.storedTime!=" " && this.storedTime.split("T")[1]!="any") {
			this.time = dojo.widget.TimePicker.util.fromRfcDateTime(this.storedTime, this.useDefaultMinutes, this.selectedTime.anyTime);
		} else if (this.useDefaultTime) {
			this.time = dojo.widget.TimePicker.util.fromRfcDateTime("", this.useDefaultMinutes, this.selectedTime.anyTime);
		} else {
			this.selectedTime.anyTime = true;
			this.time = dojo.widget.TimePicker.util.fromRfcDateTime("", 0, 1);
		}
	}

	this.initUI = function() {
		// set UI to match the currently selected time
		if(!this.selectedTime.anyTime && this.time) {
			var amPmHour = dojo.widget.TimePicker.util.toAmPmHour(this.time.getHours());
			var hour = amPmHour[0];
			var isAm = amPmHour[1];
			var minute = this.time.getMinutes();
			var minuteIndex = parseInt(minute/5);
			this.onSetSelectedHour(this.hourIndexMap[hour]);
			this.onSetSelectedMinute(this.minuteIndexMap[minuteIndex]);
			this.onSetSelectedAmPm(isAm);
		} else {
			this.onSetSelectedAnyTime();
		}
	}

	this.setDateTime = function(rfcDate) {
		this.storedTime = rfcDate;
	}
	
	this.onClearSelectedHour = function(evt) {
		this.clearSelectedHour();
	}

	this.onClearSelectedMinute = function(evt) {
		this.clearSelectedMinute();
	}

	this.onClearSelectedAmPm = function(evt) {
		this.clearSelectedAmPm();
	}

	this.onClearSelectedAnyTime = function(evt) {
		this.clearSelectedAnyTime();
		if(this.selectedTime.anyTime) {
			this.selectedTime.anyTime = false;
			this.time = dojo.widget.TimePicker.util.fromRfcDateTime("", this.useDefaultMinutes);
			this.initUI();
		}
	}

	this.clearSelectedHour = function() {
		var hourNodes = this.hourContainerNode.getElementsByTagName("td");
		for (var i=0; i<hourNodes.length; i++) {
			dojo.html.setClass(hourNodes.item(i), "");
		}
	}

	this.clearSelectedMinute = function() {
		var minuteNodes = this.minuteContainerNode.getElementsByTagName("td");
		for (var i=0; i<minuteNodes.length; i++) {
			dojo.html.setClass(minuteNodes.item(i), "");
		}
	}

	this.clearSelectedAmPm = function() {
		var amPmNodes = this.amPmContainerNode.getElementsByTagName("td");
		for (var i=0; i<amPmNodes.length; i++) {
			dojo.html.setClass(amPmNodes.item(i), "");
		}
	}

	this.clearSelectedAnyTime = function() {
		dojo.html.setClass(this.anyTimeContainerNode, "anyTimeContainer");
	}

	this.onSetSelectedHour = function(evt) {
		this.onClearSelectedAnyTime();
		this.onClearSelectedHour();
		this.setSelectedHour(evt);
		this.onSetTime();
	}

	this.setSelectedHour = function(evt) {
		if(evt && evt.target) {
			dojo.html.setClass(evt.target, this.classNames.selectedTime);
			this.selectedTime["hour"] = evt.target.innerHTML;
		} else if (!isNaN(evt)) {
			var hourNodes = this.hourContainerNode.getElementsByTagName("td");
			if(hourNodes.item(evt)) {
				dojo.html.setClass(hourNodes.item(evt), this.classNames.selectedTime);
				this.selectedTime["hour"] = hourNodes.item(evt).innerHTML;
			}
		}
		this.selectedTime.anyTime = false;
	}

	this.onSetSelectedMinute = function(evt) {
		this.onClearSelectedAnyTime();
		this.onClearSelectedMinute();
		this.setSelectedMinute(evt);
		this.selectedTime.anyTime = false;
		this.onSetTime();
	}

	this.setSelectedMinute = function(evt) {
		if(evt && evt.target) {
			dojo.html.setClass(evt.target, this.classNames.selectedTime);
			this.selectedTime["minute"] = evt.target.innerHTML;
		} else if (!isNaN(evt)) {
			var minuteNodes = this.minuteContainerNode.getElementsByTagName("td");
			if(minuteNodes.item(evt)) {
				dojo.html.setClass(minuteNodes.item(evt), this.classNames.selectedTime);
				this.selectedTime["minute"] = minuteNodes.item(evt).innerHTML;
			}
		}
	}

	this.onSetSelectedAmPm = function(evt) {
		this.onClearSelectedAnyTime();
		this.onClearSelectedAmPm();
		this.setSelectedAmPm(evt);
		this.selectedTime.anyTime = false;
		this.onSetTime();
	}

	this.setSelectedAmPm = function(evt) {
		if(evt && evt.target) {
			dojo.html.setClass(evt.target, this.classNames.selectedTime);
			this.selectedTime["amPm"] = evt.target.innerHTML;
		} else {
			evt = evt ? 0 : 1;
			var amPmNodes = this.amPmContainerNode.getElementsByTagName("td");
			if(amPmNodes.item(evt)) {
				dojo.html.setClass(amPmNodes.item(evt), this.classNames.selectedTime);
				this.selectedTime["amPm"] = amPmNodes.item(evt).innerHTML;
			}
		}
	}

	this.onSetSelectedAnyTime = function(evt) {
		this.onClearSelectedHour();
		this.onClearSelectedMinute();
		this.onClearSelectedAmPm();
		this.setSelectedAnyTime();
		this.onSetTime();
	}

	this.setSelectedAnyTime = function(evt) {
		this.selectedTime.anyTime = true;
		dojo.html.setClass(this.anyTimeContainerNode, this.classNames.selectedTime + " " + "anyTimeContainer");
	}

	this.onClick = function(evt) {
		dojo.event.browser.stopEvent(evt)
	}

	this.onSetTime = function() {
		if(this.selectedTime.anyTime) {
			this.time = new Date();
			var tempDateTime = dojo.widget.TimePicker.util.toRfcDateTime(this.time);
			this.setDateTime(tempDateTime.split("T")[0]);
		} else {
			var hour = 12;
			var minute = 0;
			var isAm = false;
			if(this.selectedTime["hour"]) {
				hour = parseInt(this.selectedTime["hour"], 10);
			}
			if(this.selectedTime["minute"]) {
				minute = parseInt(this.selectedTime["minute"], 10);
			}
			if(this.selectedTime["amPm"]) {
				isAm = (this.selectedTime["amPm"].toLowerCase() == "am");
			}
			this.time = new Date();
			this.time.setHours(dojo.widget.TimePicker.util.fromAmPmHour(hour, isAm));
			this.time.setMinutes(minute);
			this.setDateTime(dojo.widget.TimePicker.util.toRfcDateTime(this.time));
		}
	}

}
dojo.inherits(dojo.widget.html.TimePicker, dojo.widget.HtmlWidget);
